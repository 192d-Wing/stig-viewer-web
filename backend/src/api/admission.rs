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
//! A third refusal looks at the audit queue: while the pending audit writes
//! that hold an admission permit and are not restricted
//! (`db_audit::admitted_pending_gauge`; login acknowledgements and system
//! events hold no permit and are not counted) are at or above
//! [`AUDIT_BACKLOG_HIGH`] (32, the healthy bound), non-admins get 503 `server
//! busy` with `Retry-After: 5` (a backlog means writes slower than the 5 s
//! caller wait, so a 1 s retry is pointless) until the gauge falls to
//! [`AUDIT_BACKLOG_LOW`] (24). Admins are spared until
//! [`AUDIT_BACKLOG_ADMIN_HIGH`] (40, a judgment value) so incident response
//! survives pool contention, and are refused with no hysteresis beyond it; the
//! audited GETs are not spared (an unrecorded read is worse than a refused
//! one). Unadmitted GETs, `/api/health` and the admin counters stay available.
//! This is damping, not a hard bound: the requests already admitted can still
//! leave writes behind. Order of checks: penalty block, user cap (429),
//! backlog (503), global cap (503). Counted as `refusedBacklog`.
//!
//! The permit travels in [`RequestCtx::permit`]. `OwnedEvent` clones the ctx
//! into the detached audit write and detached work functions take the ctx by
//! value, so the permit lives until the write or task ends, however late.
//!
//! The body of an admitted request must keep arriving. Timing starts at the
//! first read of the body (a handler that does other work first is not
//! charged for it) and is only consulted while the client is being waited
//! for: a frame the body can deliver at once is never charged. Time between
//! a delivered frame and the next poll is the handler's, not the client's, so
//! it is added to the deadline (hyper's HTTP/1 body channel is want-driven,
//! and after a long gap in reading the next poll can return Pending even
//! though the client sent everything). What remains: a handler that stops
//! polling while the body is Pending (for example `select!`-ing away) is still
//! charged, and an abandoned body is charged at most `slow_wait`. The
//! first byte is due
//! within `DEFAULT_ADMISSION_BODY_FIRST_BYTE` (5 s); after that the body is cut off
//! once `first_byte_at + DEFAULT_ADMISSION_BODY_GRACE (10 s) + bytes_received /
//! DEFAULT_ADMISSION_BODY_MIN_RATE (64 KiB/s)` has passed, so a 500 MiB upload is fine
//! while it averages 64 KiB/s. A cut-off makes the body extractor answer 400
//! and release the permit. Each cut-off is counted (`bodyDeadline`), logged
//! with the holder's user id (throttled per user), and after
//! `BODY_PENALTY_CUTS` (3) within 60 s the user is refused admission with 429
//! for 30 s. Streaming is kept: nothing is buffered here, and the routes'
//! `DefaultBodyLimit`s still apply.
//!
//! A body can also hold a permit by staying just inside those deadlines. A
//! body is "slow" when it finishes, errors or is dropped without a cut-off and
//! its waiting on the client (time the inner body spent Pending, in stretches
//! each ended by a frame, the end, an error or a drop) is excessive. Each
//! stretch of length `d` that ends with a data frame of `n` bytes earns a rate
//! credit of `n / DEFAULT_ADMISSION_BODY_MIN_RATE` for that stretch only (credit is
//! never banked across the body, so a burst cannot pay for later stalls or a
//! trickle); its `excess` is `max(0, d - n / min_rate)`, and a stretch ending
//! in the end, an error or a drop has `n = 0`. The body is slow when the summed
//! excess exceeds `ADMITTED_BODY_SLOW_WAIT` (3 s), or any single stretch was
//! longer than that. The summed-excess clause subsumes the earlier "total wait
//! over 3 s plus `received / min_rate`" one (excess >= waited - received/rate),
//! so that clause is gone. A steady upload at or above the floor rate is never
//! slow. False-positive edge: a link averaging near the 64 KiB/s floor, with
//! chunks arriving a little slower than the rate, can accumulate excess and
//! earn a half-weight strike (one point; six in a minute block).
//! Residual by design: a body sent steadily at or above the 64 KiB/s floor is
//! never slow yet holds its permit for its whole duration (about 160 s for
//! 10 MiB), so about 7 accounts at about 1.8 MB/s in all can hold the 28
//! non-admin permits. It is indistinguishable from a legitimate slow link and
//! surfaces only through the 60 s body-wait warning. Slow bodies are counted
//! (`slowBody`), logged per user, and score `SLOW_WEIGHT` (1) penalty points
//! against `CUT_WEIGHT` (2) for a cut-off; the block triggers at
//! `BODY_PENALTY_CUTS * CUT_WEIGHT` (6) points in 60 s, so three cut-offs or
//! six slow bodies block for 30 s. Setting `slow_weight` to 0 counts and logs
//! only. Residual: stalls under 3 s each, many per request, are not counted as
//! slow; a user whose body-wait within 60 s reaches `BODY_WAIT_ALERT` (60 s)
//! is logged (throttled per user) instead. Blocks and backlog latch changes
//! are logged. The top users by windowed body-wait time are named in the
//! refusal log lines (ids only). A handler that abandons a body mid-wait is
//! charged at most `slow_wait` for the open stretch (see the want-driven note
//! above).
//!
//! Admitted: every non-read method, and the GETs in [`AUDITED_READ_ROUTES`]
//! (the only GETs that record an event). The exception is a mutation that
//! `viewer_guard` will refuse (a `viewer` outside its allowlist): it takes no
//! permit, is never counted against a cap or the backlog, and is answered 403
//! with an `authz.denied` row (bounded by the rate limiter and the per-user
//! denied sub-cap), never 429 or 503. Other GETs are not admitted:
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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
/// Body cut-offs within [`BODY_PENALTY_WINDOW`] after which a user is refused
/// admission for [`BODY_PENALTY_BLOCK`].
pub const BODY_PENALTY_CUTS: u32 = 3;
pub const BODY_PENALTY_WINDOW: Duration = Duration::from_secs(60);
pub const BODY_PENALTY_BLOCK: Duration = Duration::from_secs(30);
/// How long a body waited on the client: in all, the longest single stretch,
/// and the sum over stretches of each stretch's time beyond its own rate credit.
#[derive(Debug, Clone, Copy, Default)]
struct BodyWait {
    waited: Duration,
    longest: Duration,
    excess: Duration,
}

/// A body that waited on the client more than this (plus the rate credit for
/// the bytes it received) is "slow" even though it met its deadlines.
pub const ADMITTED_BODY_SLOW_WAIT: Duration = Duration::from_secs(3);
/// A user whose body-wait time within the penalty window reaches this is
/// logged (the residual for stalls too short to be "slow").
const BODY_WAIT_ALERT: Duration = Duration::from_secs(60);
/// Body waits shorter than this are not accounted at all (hot path).
const BODY_WAIT_NOTE_FLOOR: Duration = Duration::from_secs(1);
/// Penalty points for a body cut-off, and for a slow body.
pub const CUT_WEIGHT: u32 = 2;
pub const SLOW_WEIGHT: u32 = 1;
/// Pending permit-holding, non-restricted audit writes at or above which
/// non-admins are refused (503). The healthy bound: every one of the
/// `MAX_IN_FLIGHT` permits holds one write. Permit-less writes (login
/// acknowledgements, system events) are not counted.
pub const AUDIT_BACKLOG_HIGH: u32 = MAX_IN_FLIGHT;
/// The refusal for non-admins ends once the gauge is at or below this.
pub const AUDIT_BACKLOG_LOW: u32 = 24;
/// Admins are refused at or above this (a judgment constant: between the
/// healthy bound and the queue's non-restricted share).
pub const AUDIT_BACKLOG_ADMIN_HIGH: u32 = 40;
/// `Retry-After` for a backlog refusal.
const BACKLOG_RETRY_AFTER_SECS: &str = "5";
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
    pub slow_wait: Duration,
    /// Penalty points per slow body (0: count and log only).
    pub slow_weight: u32,
}

impl From<crate::config::AdmissionBody> for BodyLimits {
    fn from(c: crate::config::AdmissionBody) -> Self {
        Self {
            first_byte: c.first_byte,
            grace: c.grace,
            min_rate: c.min_rate,
            ..Self::default()
        }
    }
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            first_byte: crate::config::DEFAULT_ADMISSION_BODY_FIRST_BYTE,
            grace: crate::config::DEFAULT_ADMISSION_BODY_GRACE,
            min_rate: crate::config::DEFAULT_ADMISSION_BODY_MIN_RATE,
            penalty_cuts: BODY_PENALTY_CUTS,
            penalty_window: BODY_PENALTY_WINDOW,
            penalty_block: BODY_PENALTY_BLOCK,
            slow_wait: ADMITTED_BODY_SLOW_WAIT,
            slow_weight: SLOW_WEIGHT,
        }
    }
}

/// Audit-queue slots kept free for events with no permit: `auth.notice_ack`
/// (no request ctx) and system events (scheduled sync).
pub const UNADMITTED_RESERVE: u32 = 16;

const _: () = assert!(ADMIN_RESERVE < MAX_IN_FLIGHT);
const _: () = assert!(AUDIT_BACKLOG_LOW < AUDIT_BACKLOG_HIGH);
const _: () = assert!(AUDIT_BACKLOG_HIGH <= AUDIT_BACKLOG_ADMIN_HIGH);
const _: () = assert!(AUDIT_BACKLOG_ADMIN_HIGH < MAX_PENDING_WRITES - MAX_DENIED_PENDING);

// Handlers await each audit write in turn, so an admitted request has at most
// one non-restricted write pending at a time on a healthy pool, and a late
// write keeps its permit. Non-restricted pending writes from admitted requests
// are therefore at most `MAX_IN_FLIGHT`, whatever the role or
// `RATE_LIMIT_BURST`, and the reserve covers the permit-less writers.
const _: () = assert!(
    MAX_IN_FLIGHT + UNADMITTED_RESERVE <= MAX_PENDING_WRITES - MAX_DENIED_PENDING,
    "admission caps must leave the audit queue's non-restricted share intact"
);
const _: () = assert!(
    AUDIT_BACKLOG_HIGH + UNADMITTED_RESERVE <= MAX_PENDING_WRITES - MAX_DENIED_PENDING,
    "the backlog mark must leave the unadmitted reserve free"
);

pub use crate::api::audit::AUDITED_READ_ROUTES;

const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Per-reason rate limit for the refusal log line, counting what it hid.
#[derive(Debug, Default)]
struct WarnThrottle {
    last: [Option<Instant>; 3],
    suppressed: [u64; 3],
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

/// The user's penalty entry, created if absent. When the table is full of
/// live entries nothing is created (`None`): the caller's count is kept but
/// there is no per-user state.
fn penalty_entry<'a>(
    s: &'a mut Counts,
    b: &BodyLimits,
    user_id: &str,
    now: Instant,
) -> Option<&'a mut Penalty> {
    if !s.penalties.contains_key(user_id) && s.penalties.len() >= MAX_TRACKED_USERS {
        s.penalties.retain(|_, p| {
            p.blocked_until.is_some_and(|t| now < t)
                || p.wait_live(now, b.penalty_window)
                || p.strikes
                    .iter()
                    .any(|(t, _)| now.saturating_duration_since(*t) < b.penalty_window)
        });
        if s.penalties.len() >= MAX_TRACKED_USERS {
            return None;
        }
    }
    Some(s.penalties.entry(user_id.to_owned()).or_default())
}

/// Add `weight` penalty points for `user_id`; block them once the points in
/// the window reach `penalty_cuts * CUT_WEIGHT` (the points are then cleared).
/// Returns the points that caused a block, when this strike blocked.
fn add_strike(
    s: &mut Counts,
    b: &BodyLimits,
    user_id: &str,
    weight: u32,
    now: Instant,
) -> Option<u32> {
    let p = penalty_entry(s, b, user_id, now)?;
    p.strikes
        .retain(|(t, _)| now.saturating_duration_since(*t) < b.penalty_window);
    p.strikes.push((now, weight));
    let points: u32 = p
        .strikes
        .iter()
        .map(|(_, w)| *w)
        .fold(0, u32::saturating_add);
    if points >= b.penalty_cuts.saturating_mul(CUT_WEIGHT) {
        p.strikes.clear();
        p.blocked_until = Some(now + b.penalty_block);
        return Some(points);
    }
    None
}

/// Log a block the moment it is set (never throttled: it is rare, bounded by
/// the block length, and the event an operator needs).
fn log_block(user_id: &str, blocked: Option<u32>, b: &BodyLimits) {
    if let Some(points) = blocked {
        tracing::warn!(
            target: "audit",
            user_id = %crate::db_audit::audit_safe_id(user_id),
            points,
            reason = "body_penalty_block",
            until_ms = b.penalty_block.as_millis() as u64,
            "user blocked from admission after repeated slow or cut-off request bodies"
        );
    }
}

/// Recent penalty strikes (time, points) and body-wait time of one user, and
/// any admission block they earned.
#[derive(Debug, Default)]
struct Penalty {
    strikes: Vec<(Instant, u32)>,
    blocked_until: Option<Instant>,
    /// Start of the current body-wait window, and the wait summed in it.
    wait_window_start: Option<Instant>,
    waited: Duration,
}

impl Penalty {
    fn wait_live(&self, now: Instant, window: Duration) -> bool {
        self.wait_window_start
            .is_some_and(|t| now.saturating_duration_since(t) < window)
    }
}

/// `"a(3), b(2) (+4 more)"`, or `"none"`, with each id made log-safe.
fn format_holders(top: &[(String, u32)], total: usize) -> String {
    format_listed(top, total, "")
}

/// [`format_holders`] with a unit after each value (`"a(42s)"`).
fn format_listed<N: std::fmt::Display>(top: &[(String, N)], total: usize, unit: &str) -> String {
    if top.is_empty() {
        return "none".to_string();
    }
    let mut out = top
        .iter()
        .map(|(i, n)| format!("{}({n}{unit})", crate::db_audit::audit_safe_id(i)))
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
    /// The audit queue's backlog is at its high-water mark.
    Backlog = 2,
}

/// Counters reported on `GET /api/admin/failure-counters`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionStats {
    pub in_flight: u32,
    pub refused_user: u64,
    pub refused_global: u64,
    pub refused_backlog: u64,
    pub body_deadline: u64,
    pub slow_body: u64,
}

#[derive(Debug, Default)]
struct Counts {
    /// Latched while the audit backlog is between the low and high marks.
    backlogged: bool,
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
    refused_backlog: AtomicU64,
    warn: Mutex<WarnThrottle>,
    cut_warn: Mutex<UserWarnThrottle>,
    slow_warn: Mutex<UserWarnThrottle>,
    wait_warn: Mutex<UserWarnThrottle>,
    body_cut_offs: AtomicU64,
    slow_bodies: AtomicU64,
    /// Pending permit-holding, non-restricted audit writes (see
    /// `db_audit::WriteQueue::admitted_gauge`).
    backlog: &'static AtomicU32,
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

/// A gauge nothing writes (every constructor but [`Admission::new`]), so a
/// test's admission is not affected by the process-wide audit queue.
fn private_gauge() -> &'static AtomicU32 {
    Box::leak(Box::new(AtomicU32::new(0)))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Admission {
    /// The production admission, wired to the process-wide audit queue.
    pub fn new() -> Arc<Self> {
        Self::configured(BodyLimits::default())
    }

    /// The production admission with configured body limits.
    pub fn configured(body: BodyLimits) -> Arc<Self> {
        Self::build(
            MAX_IN_FLIGHT,
            MAX_USER_IN_FLIGHT,
            ADMIN_RESERVE,
            body,
            crate::db_audit::admitted_pending_gauge(),
        )
    }

    /// Default caps over a caller-owned backlog gauge (tests).
    #[cfg(test)]
    pub(crate) fn with_backlog(gauge: &'static AtomicU32) -> Arc<Self> {
        Self::build(
            MAX_IN_FLIGHT,
            MAX_USER_IN_FLIGHT,
            ADMIN_RESERVE,
            BodyLimits::default(),
            gauge,
        )
    }

    /// Caps with no admin reserve (tests).
    pub fn with_caps(cap: u32, user_cap: u32) -> Arc<Self> {
        Self::with_limits(cap, user_cap, 0)
    }

    /// Default caps with other body limits (tests).
    pub fn with_body(body: BodyLimits) -> Arc<Self> {
        Self::build(
            MAX_IN_FLIGHT,
            MAX_USER_IN_FLIGHT,
            ADMIN_RESERVE,
            body,
            private_gauge(),
        )
    }

    pub fn with_limits(cap: u32, user_cap: u32, admin_reserve: u32) -> Arc<Self> {
        Self::build(
            cap,
            user_cap,
            admin_reserve,
            BodyLimits::default(),
            private_gauge(),
        )
    }

    fn build(
        cap: u32,
        user_cap: u32,
        admin_reserve: u32,
        mut body: BodyLimits,
        backlog: &'static AtomicU32,
    ) -> Arc<Self> {
        body.min_rate = body.min_rate.max(1);
        Arc::new(Self {
            state: Mutex::new(Counts::default()),
            idle: Notify::new(),
            refused_user: AtomicU64::new(0),
            refused_global: AtomicU64::new(0),
            refused_backlog: AtomicU64::new(0),
            warn: Mutex::new(WarnThrottle::default()),
            cut_warn: Mutex::new(UserWarnThrottle::default()),
            slow_warn: Mutex::new(UserWarnThrottle::default()),
            wait_warn: Mutex::new(UserWarnThrottle::default()),
            body_cut_offs: AtomicU64::new(0),
            slow_bodies: AtomicU64::new(0),
            backlog,
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
    /// one lock. A user with too many recent penalty points is refused (as
    /// `User`) until their block ends. While the audit backlog is high,
    /// requests are refused as `Backlog` (see the module docs).
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
        let n = self.backlog.load(Ordering::Relaxed);
        if n >= AUDIT_BACKLOG_HIGH && !s.backlogged {
            s.backlogged = true;
            tracing::warn!(target: "audit", pending = n, "audit backlog high: refusing non-admin requests");
        } else if n <= AUDIT_BACKLOG_LOW && s.backlogged {
            s.backlogged = false;
            tracing::info!(target: "audit", pending = n, "audit backlog drained: admitting requests again");
        }
        if if admin {
            n >= AUDIT_BACKLOG_ADMIN_HIGH
        } else {
            s.backlogged
        } {
            return Err(Refusal::Backlog);
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

    pub fn stats(&self) -> AdmissionStats {
        AdmissionStats {
            in_flight: self.in_flight(),
            refused_user: self.refused_user.load(Ordering::Relaxed),
            refused_global: self.refused_global.load(Ordering::Relaxed),
            refused_backlog: self.refused_backlog.load(Ordering::Relaxed),
            body_deadline: self.body_cut_offs.load(Ordering::Relaxed),
            slow_body: self.slow_bodies.load(Ordering::Relaxed),
        }
    }

    /// Record that `user_id`'s body was cut off: count it, score
    /// [`CUT_WEIGHT`] points (a block follows at
    /// `penalty_cuts * CUT_WEIGHT` within the window), and log it (ids only,
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
        let blocked = add_strike(&mut lock(&self.state), &b, user_id, CUT_WEIGHT, now);
        log_block(user_id, blocked, &b);
    }

    /// A body is done (ended, errored, cut off or dropped) after waiting
    /// `waited` on the client for `received` bytes. Does nothing but a
    /// comparison for a body that barely waited. Otherwise the wait goes into
    /// the user's window, and a body that was not cut off but waited more than
    /// `slow_wait` plus the rate credit is counted, logged and scored.
    fn note_body_done(&self, user_id: &str, wait: BodyWait, received: u64, cut: bool) {
        self.note_body_wait_at(user_id, wait, received, cut, Instant::now());
    }

    /// Whole-body rule only (no per-stretch information): the credit is
    /// taken off the total, as if banked.
    #[cfg(test)]
    fn note_body_done_at(
        &self,
        user_id: &str,
        waited: Duration,
        received: u64,
        cut: bool,
        now: Instant,
    ) {
        let credit = Duration::from_secs_f64(received as f64 / self.body.min_rate as f64);
        let wait = BodyWait {
            waited,
            longest: Duration::ZERO,
            excess: waited.saturating_sub(credit),
        };
        self.note_body_wait_at(user_id, wait, received, cut, now);
    }

    fn note_body_wait_at(
        &self,
        user_id: &str,
        wait: BodyWait,
        received: u64,
        cut: bool,
        now: Instant,
    ) {
        let BodyWait {
            waited,
            longest,
            excess,
        } = wait;
        if waited < BODY_WAIT_NOTE_FLOOR {
            return;
        }
        let b = self.body;
        let slow = !cut && (longest > b.slow_wait || excess > b.slow_wait);
        let mut heavy = false;
        let mut blocked = None;
        {
            let mut s = lock(&self.state);
            if let Some(p) = penalty_entry(&mut s, &b, user_id, now) {
                if !p.wait_live(now, b.penalty_window) {
                    p.wait_window_start = Some(now);
                    p.waited = Duration::ZERO;
                }
                p.waited = p.waited.saturating_add(waited);
                heavy = p.waited >= BODY_WAIT_ALERT;
            }
            if slow && b.slow_weight > 0 {
                blocked = add_strike(&mut s, &b, user_id, b.slow_weight, now);
            }
        }
        log_block(user_id, blocked, &b);
        if heavy && !slow {
            if let Some(hidden) = lock(&self.wait_warn).decide(user_id, now) {
                tracing::warn!(
                    target: "audit",
                    user_id = %crate::db_audit::audit_safe_id(user_id),
                    window_s = b.penalty_window.as_secs(),
                    suppressed = hidden,
                    "request bodies waited on the client a long time in total while holding admission permits"
                );
            }
        }
        if slow {
            self.slow_bodies.fetch_add(1, Ordering::Relaxed);
            if let Some(hidden) = lock(&self.slow_warn).decide(user_id, now) {
                tracing::warn!(
                    target: "audit",
                    user_id = %crate::db_audit::audit_safe_id(user_id),
                    waited_ms = waited.as_millis() as u64,
                    bytes = received,
                    suppressed = hidden,
                    "request body slow: waited on the client while holding an admission permit"
                );
            }
        }
    }

    /// The users with the most body-wait time in their current window (wait
    /// desc, then id), for the refusal log lines.
    fn top_body_wait_summary(&self) -> String {
        let now = Instant::now();
        let window = self.body.penalty_window;
        let s = lock(&self.state);
        let mut waits: Vec<(String, u64)> = s
            .penalties
            .iter()
            .filter(|(_, p)| p.wait_live(now, window))
            .map(|(u, p)| (u.clone(), p.waited.as_secs()))
            .collect();
        waits.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let total = waits.len();
        waits.truncate(MAX_LISTED_USERS);
        format_listed(&waits, total, "s")
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
            Refusal::Backlog => &self.refused_backlog,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let hidden = lock(&self.warn).decide(why, Instant::now());
        if let Some(hidden) = hidden {
            let crowded = matches!(why, Refusal::Global | Refusal::Backlog);
            tracing::warn!(
                target: "audit",
                user_id = %crate::db_audit::audit_safe_id(user_id),
                reason = match why {
                    Refusal::User => "user_cap",
                    Refusal::Global => "global_cap",
                    Refusal::Backlog => "audit_backlog",
                },
                suppressed = hidden,
                pending = self.backlog.load(Ordering::Relaxed),
                top_holders = %if crowded { self.top_holders_summary() } else { String::new() },
                top_body_wait = %if crowded { self.top_body_wait_summary() } else { String::new() },
                "request refused: too many audited requests in flight"
            );
        }
    }
}

/// A request body that errors once it falls behind the minimum rate (see the
/// module docs). The clock starts at the first read, and is only consulted
/// when the inner body returns Pending (the client is being waited for), so a
/// frame the inner body can deliver at once is never charged. The time between
/// a delivered frame and the next poll is handler time and extends the
/// deadline (`paused`). A handler that stops polling while the body is Pending
/// is still charged. Streams frames from the inner body unchanged.
struct DeadlineBody {
    inner: Body,
    adm: Arc<Admission>,
    user_id: String,
    origin: Option<tokio::time::Instant>,
    first_byte_at: Option<tokio::time::Instant>,
    /// When the last frame was delivered to the handler, and the handler time
    /// (gaps between a delivered frame and the next poll) credited so far.
    last_frame_at: Option<tokio::time::Instant>,
    paused: Duration,
    received: u64,
    ended: bool,
    failed: bool,
    /// When the current Pending stretch began, and the Pending time so far.
    wait_since: Option<tokio::time::Instant>,
    waited: Duration,
    /// The longest single Pending stretch, and the summed per-stretch excess.
    longest: Duration,
    excess: Duration,
    /// The admission has been told how this body went (once).
    noted: bool,
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
            last_frame_at: None,
            paused: Duration::ZERO,
            received: 0,
            ended,
            failed: false,
            wait_since: None,
            waited: Duration::ZERO,
            longest: Duration::ZERO,
            excess: Duration::ZERO,
            noted: false,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }

    /// Fold an open Pending stretch ending at `now` into `waited`.
    /// `bytes` is the data frame that ended the stretch (0 for none).
    fn close_wait(&mut self, now: tokio::time::Instant, bytes: u64) {
        if let Some(t) = self.wait_since.take() {
            self.fold(now.saturating_duration_since(t), bytes);
        }
    }

    fn fold(&mut self, stretch: Duration, bytes: u64) {
        let credit = Duration::from_secs_f64(bytes as f64 / self.adm.body.min_rate as f64);
        self.waited = self.waited.saturating_add(stretch);
        self.longest = self.longest.max(stretch);
        self.excess = self.excess.saturating_add(stretch.saturating_sub(credit));
    }

    /// Report the body's wait to the admission, once.
    fn finish(&mut self, cut: bool) {
        if !self.noted {
            self.noted = true;
            let wait = BodyWait {
                waited: self.waited,
                longest: self.longest,
                excess: self.excess,
            };
            self.adm
                .note_body_done(&self.user_id, wait, self.received, cut);
        }
    }

    fn deadline(&self, origin: tokio::time::Instant) -> tokio::time::Instant {
        let b = &self.adm.body;
        match self.first_byte_at {
            None => origin + b.first_byte,
            Some(t) => {
                t + b.grace
                    + self.paused
                    + Duration::from_secs_f64(self.received as f64 / b.min_rate as f64)
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
        if let Some(t) = this.last_frame_at.take() {
            this.paused = this.paused.saturating_add(now.saturating_duration_since(t));
        }
        let origin = *this.origin.get_or_insert(now);
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                this.close_wait(now, 0);
                this.ended = true;
                this.finish(false);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                this.close_wait(now, frame.data_ref().map_or(0, |d| d.len() as u64));
                if let Some(d) = frame.data_ref().filter(|d| !d.is_empty()) {
                    this.received += d.len() as u64;
                    this.first_byte_at.get_or_insert(now);
                }
                if this.inner.is_end_stream() {
                    this.ended = true;
                    this.finish(false);
                } else {
                    this.last_frame_at = Some(now);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(other) => {
                this.close_wait(now, 0);
                this.finish(false);
                Poll::Ready(other)
            }
            Poll::Pending => {
                this.wait_since.get_or_insert(now);
                // Waiting on the client: keep a timer armed for the deadline.
                let deadline = this.deadline(origin);
                if this.timer.deadline() != deadline {
                    this.timer.as_mut().reset(deadline);
                }
                if this.timer.as_mut().poll(cx).is_ready() {
                    this.failed = true;
                    this.close_wait(now, 0);
                    this.adm.note_cut_off(&this.user_id);
                    this.finish(true);
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

impl Drop for DeadlineBody {
    /// A client that disconnects, or a handler that abandons the body, still
    /// reports what the body waited. A body never read reports nothing.
    fn drop(&mut self) {
        if self.origin.is_some() && !self.noted {
            // The handler may simply have stopped reading, which is not the
            // client's wait: charge an open stretch at most `slow_wait`.
            if let Some(t) = self.wait_since.take() {
                let open = tokio::time::Instant::now().saturating_duration_since(t);
                self.fold(open.min(self.adm.body.slow_wait), 0);
            }
            self.finish(false);
        }
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
    // A viewer mutation `viewer_guard` will refuse takes no permit: it gets
    // the 403 and its `authz.denied` row, never a 429 or 503.
    // Invariant: skipping is safe only because `viewer_guard` answers 403
    // without reading the body. `rate_limit` is the outermost layer of
    // `protected_stack`, so denied viewers are still rate-limited, and further
    // `authz.denied` writes are shed by the per-user restricted sub-cap.
    if crate::api::viewer_guard::denies(&user.role, req.method(), req.uri().path()) {
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
            let (status, msg, retry_after) = match why {
                Refusal::User => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many concurrent requests",
                    "1",
                ),
                Refusal::Global => (StatusCode::SERVICE_UNAVAILABLE, "server busy", "1"),
                Refusal::Backlog => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server busy",
                    BACKLOG_RETRY_AFTER_SECS,
                ),
            };
            (
                status,
                [("Retry-After", retry_after)],
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

    /// Open a POST with a Content-Length of 75000, send no body, and read the
    /// response status line (real-socket smoke: wide margins only).
    async fn raw_status_header_only(base: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = base.trim_start_matches("http://");
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let head = "POST /api/body HTTP/1.1\r\nHost: x\r\nx-user: slow-body\r\n\
                    Content-Length: 75000\r\n\r\n";
        conn.write_all(head.as_bytes()).await.unwrap();
        // `conn` stays open until the response is read.
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut buf))
            .await
            .expect("no response")
            .unwrap();
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

    /// The `app` router driven in-process (no sockets), so a paused clock is
    /// sound: nothing waits on kernel I/O.
    fn paused_app(b: BodyLimits) -> (Router, Arc<Admission>, Arc<Gate>) {
        let (mut state, _dir) = lazy_state();
        state.admission = Admission::with_body(b);
        let adm = state.admission.clone();
        let (gate, _entered) = Gate::new();
        (app(state, gate.clone()), adm, gate)
    }

    /// A request body made of [`Timed`] steps.
    fn timed_body(steps: &[(u64, Option<usize>)]) -> Body {
        let steps = steps
            .iter()
            .map(|&(ms, n)| {
                (
                    Duration::from_millis(ms),
                    n.map(|n| Bytes::from(vec![b'x'; n])),
                )
            })
            .collect();
        Body::new(Timed { steps, sleep: None })
    }

    async fn post_body(router: &Router, path: &str, user: &str, body: Body) -> Response {
        use tower::ServiceExt;
        router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("x-user", user)
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_header_only_post_over_a_real_socket_is_cut_off_and_attributed() {
        // A huge grace shows it is the first-byte deadline that fires.
        let (base, adm, _gate) = body_app(limits(400, 600_000, 1000)).await;
        let started = std::time::Instant::now();
        assert!(raw_status_header_only(&base).await.contains(" 400"));
        assert!(started.elapsed() < Duration::from_secs(5));
        adm.idle().await;
        assert_eq!(adm.in_flight(), 0);
        // Counted, and recorded against the holder.
        assert_eq!(adm.stats().body_deadline, 1);
        assert_eq!(lock(&adm.state).penalties["slow-body"].strikes.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_header_only_post_is_cut_off_at_the_first_byte_deadline() {
        let (router, adm, _gate) = paused_app(limits(400, 600_000, 1000));
        let t0 = tokio::time::Instant::now();
        let r = post_body(
            &router,
            "/api/body",
            "slow-body",
            timed_body(&[(10_000_000, Some(1))]),
        )
        .await;
        assert_eq!(r.status().as_u16(), 400);
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(400) && waited < Duration::from_secs(1),
            "{waited:?}"
        );
        adm.idle().await;
        assert_eq!(adm.in_flight(), 0);
        assert_eq!(adm.stats().body_deadline, 1);
        assert_eq!(lock(&adm.state).penalties["slow-body"].strikes.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_drip_below_the_minimum_rate_is_cut_off() {
        // 100 B/s against a 1000 B/s minimum, so the deadline only creeps
        // ahead of the 10 ms pace once the 400 ms grace is used up.
        let (router, adm, _gate) = paused_app(limits(400, 400, 1000));
        let steps: Vec<_> = (0..200).map(|_| (10, Some(1))).chain([(0, None)]).collect();
        let r = post_body(&router, "/api/body", "slow-body", timed_body(&steps)).await;
        assert_eq!(r.status().as_u16(), 400);
        adm.idle().await;
        assert_eq!(adm.in_flight(), 0);
        assert_eq!(adm.stats().body_deadline, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_above_the_minimum_rate_survives_past_the_grace() {
        // About 600 ms in all against a 400 ms grace, at 125 kB/s against a
        // 100 kB/s minimum.
        let (router, adm, _gate) = paused_app(limits(400, 400, 100_000));
        let steps: Vec<_> = (0..15)
            .map(|_| (40, Some(5000)))
            .chain([(0, None)])
            .collect();
        let r = post_body(&router, "/api/body", "slow-body", timed_body(&steps)).await;
        assert_eq!(r.status().as_u16(), 200);
        adm.idle().await;
        assert_eq!(adm.stats().body_deadline, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_does_not_cancel_a_handler_after_the_body_is_complete() {
        let (router, adm, _gate) = paused_app(limits(500, 500, 1000));
        let r = post_body(
            &router,
            "/api/slow",
            "slow-handler",
            timed_body(&[(0, Some(4)), (0, None)]),
        )
        .await;
        // The handler ran for 1.5 s, well past the 500 ms limits.
        assert_eq!(r.status().as_u16(), 200);
        adm.idle().await;
        assert_eq!(adm.stats().body_deadline, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_handler_that_reads_the_body_late_is_not_charged_for_its_delay() {
        let (router, adm, _gate) = paused_app(limits(300, 300, 1000));
        let r = post_body(
            &router,
            "/api/late",
            "late-reader",
            timed_body(&[(0, Some(13)), (0, None)]),
        )
        .await;
        // The body was ready at once; the handler read it 900 ms later.
        assert_eq!(r.status().as_u16(), 200);
        adm.idle().await;
        assert_eq!(adm.stats().body_deadline, 0);
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
        assert_eq!(a.stats().body_deadline, 3);
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

    #[tokio::test(start_paused = true)]
    async fn three_cut_offs_block_the_user_through_the_middleware() {
        let (router, adm, gate) = paused_app(limits(150, 600_000, 1000));
        for _ in 0..BODY_PENALTY_CUTS {
            let r = post_body(
                &router,
                "/api/body",
                "slow-body",
                timed_body(&[(10_000_000, Some(1))]),
            )
            .await;
            assert_eq!(r.status().as_u16(), 400);
        }
        adm.idle().await;
        assert_eq!(adm.stats().body_deadline, u64::from(BODY_PENALTY_CUTS));
        // "slow-body" is now refused before the handler; others are not.
        let r = post_body(&router, "/api/gate", "slow-body", Body::empty()).await;
        assert_eq!(r.status().as_u16(), 429);
        assert_eq!(r.headers().get("retry-after").unwrap(), "1");
        assert_eq!(gate.entered.load(Ordering::SeqCst), 0);
        let r = post_body(&router, "/api/fast", "innocent", Body::empty()).await;
        assert_eq!(r.status().as_u16(), 200);
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
        assert_eq!(adm.stats().body_deadline, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pending_body_past_the_deadline_is_cut_off() {
        let (mut b, adm) = scripted(false);
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        // Nothing more is coming: the timer (paused clock auto-advances) fires.
        assert!(next_frame(&mut b).await.unwrap().is_err());
        assert_eq!(adm.stats().body_deadline, 1);
        // Once cut off, it stays an error without counting again.
        assert!(next_frame(&mut b).await.unwrap().is_err());
        assert_eq!(adm.stats().body_deadline, 1);
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
                .route(
                    "/api/notifications/mark-read",
                    post(|| async { StatusCode::OK }),
                )
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
        crate::crypto::tls::http_client_builder()
            .build()
            .unwrap()
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
        expect_refused_after(resp, status, msg, "1").await;
    }

    async fn expect_refused_after(resp: reqwest::Response, status: u16, msg: &str, retry: &str) {
        assert_eq!(resp.status().as_u16(), status);
        assert_eq!(resp.headers().get("retry-after").unwrap(), retry);
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
        assert_eq!(
            adm.stats(),
            AdmissionStats {
                in_flight: 4,
                refused_user: 1,
                ..Default::default()
            }
        );
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
        assert_eq!(
            adm.stats(),
            AdmissionStats {
                in_flight: 3,
                refused_global: 1,
                ..Default::default()
            }
        );
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
        assert_eq!(
            adm.stats(),
            AdmissionStats {
                in_flight: 4,
                ..Default::default()
            }
        );
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
    async fn an_allowlisted_viewer_mutation_is_still_admitted_and_refused_at_the_cap() {
        let (state, _dir) = lazy_state();
        let adm = state.admission.clone();
        let (gate, _entered) = Gate::new();
        let base = serve(app(state, gate)).await;
        let _held: Vec<_> = (0..4).map(|_| adm.try_admit("viewer-v").unwrap()).collect();
        // The allowlisted mutation passes `viewer_guard`, so it takes a
        // permit and is refused at the cap. (A non-allowlisted one would be
        // a 403 with an audit write, which this lazy-pool test must avoid.)
        expect_refused(
            call(&base, "POST", "/api/notifications/mark-read", "viewer-v").await,
            429,
            "too many concurrent requests",
        )
        .await;
        assert_eq!(adm.stats().refused_user, 1);
    }

    /// An inner body that, for each step, waits `delay` and then yields the
    /// frame (or ends on `None`).
    struct Timed {
        steps: std::collections::VecDeque<(Duration, Option<Bytes>)>,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl http_body::Body for Timed {
        type Data = Bytes;
        type Error = axum::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, axum::Error>>> {
            let Some(&(delay, _)) = self.steps.front() else {
                return Poll::Ready(None);
            };
            let sleep = self
                .sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
            match self.steps.pop_front() {
                Some((_, Some(b))) => Poll::Ready(Some(Ok(http_body::Frame::data(b)))),
                _ => Poll::Ready(None),
            }
        }
    }

    fn timed(steps: &[(u64, Option<usize>)], b: BodyLimits) -> (DeadlineBody, Arc<Admission>) {
        let adm = Admission::with_body(b);
        let steps = steps
            .iter()
            .map(|&(ms, n)| {
                (
                    Duration::from_millis(ms),
                    n.map(|n| Bytes::from(vec![b'x'; n])),
                )
            })
            .collect();
        let inner = Body::new(Timed { steps, sleep: None });
        (DeadlineBody::new(inner, adm.clone(), "u".into()), adm)
    }

    async fn drain_body(b: &mut DeadlineBody) -> usize {
        let mut errors = 0;
        while let Some(f) = next_frame(b).await {
            errors += usize::from(f.is_err());
            if f.is_err() {
                break;
            }
        }
        errors
    }

    fn points(a: &Admission, user: &str) -> u32 {
        lock(&a.state)
            .penalties
            .get(user)
            .map_or(0, |p| p.strikes.iter().map(|(_, w)| *w).sum())
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_but_compliant_body_is_counted_scored_and_named() {
        // First byte at 4.9 s (due by 5 s), done at 14.9 s (due by ~14.9 s).
        let (mut b, adm) = timed(&[(4900, Some(4)), (10_000, None)], BodyLimits::default());
        assert_eq!(drain_body(&mut b).await, 0);
        // Polling after the end does not count it again.
        assert!(next_frame(&mut b).await.is_none());
        drop(b);
        let st = adm.stats();
        assert_eq!((st.body_deadline, st.slow_body), (0, 1));
        assert_eq!(points(&adm, "u"), SLOW_WEIGHT);
        assert_eq!(adm.top_body_wait_summary(), "u(14s)");
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_body_is_not_slow_and_leaves_no_state() {
        let (mut b, adm) = scripted(true);
        assert_eq!(drain_body(&mut b).await, 0);
        drop(b);
        assert_eq!(adm.stats().slow_body, 0);
        assert!(lock(&adm.state).penalties.is_empty());
        assert_eq!(adm.top_body_wait_summary(), "none");
    }

    #[test]
    fn a_large_body_above_the_minimum_rate_with_brief_stalls_is_not_slow() {
        let a = Admission::with_body(BodyLimits::default());
        let t0 = Instant::now();
        // 640 KiB earns 10 s of credit: 12 s waited is within 3 s + 10 s.
        a.note_body_done_at("u", Duration::from_secs(12), 640 * 1024, false, t0);
        assert_eq!(a.stats().slow_body, 0);
        assert_eq!(points(&a, "u"), 0);
        // Past it, it is slow.
        a.note_body_done_at("u", Duration::from_secs(14), 640 * 1024, false, t0);
        assert_eq!(a.stats().slow_body, 1);
    }

    #[test]
    fn padding_a_body_past_64_kib_does_not_bypass_the_slow_rule() {
        let a = Admission::with_body(BodyLimits::default());
        a.note_body_done_at(
            "u",
            Duration::from_secs(12),
            65 * 1024,
            false,
            Instant::now(),
        );
        assert_eq!(a.stats().slow_body, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cut_off_body_scores_the_cut_weight_and_is_not_also_slow() {
        let (mut b, adm) = scripted(false);
        assert_eq!(drain_body(&mut b).await, 1);
        drop(b);
        let st = adm.stats();
        assert_eq!((st.body_deadline, st.slow_body), (1, 0));
        assert_eq!(points(&adm, "u"), CUT_WEIGHT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_dropped_mid_wait_is_counted_once() {
        // A 4 s stall that ended, then a second wait the client abandons.
        let (mut b, adm) = timed(&[(4000, Some(1)), (60_000, Some(1))], BodyLimits::default());
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        let pending = std::future::poll_fn(|cx| {
            Poll::Ready(http_body::Body::poll_frame(Pin::new(&mut b), cx).is_pending())
        })
        .await;
        assert!(pending);
        tokio::time::advance(Duration::from_secs(4)).await;
        drop(b);
        assert_eq!(adm.stats().slow_body, 1);
        assert_eq!(adm.stats().body_deadline, 0);
        // A body that was never read reports nothing.
        let (b2, adm2) = timed(&[(60_000, Some(1))], BodyLimits::default());
        drop(b2);
        assert_eq!(adm2.stats(), AdmissionStats::default());
    }

    #[test]
    fn dropping_a_polled_body_outside_a_runtime_does_not_panic() {
        // Shutdown can drop a body after the runtime is gone.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (mut b, adm) = rt.block_on(async {
            let (mut b, adm) = timed(&[(60_000, Some(1))], BodyLimits::default());
            let pending = std::future::poll_fn(|cx| {
                Poll::Ready(http_body::Body::poll_frame(Pin::new(&mut b), cx).is_pending())
            })
            .await;
            assert!(pending);
            (b, adm)
        });
        drop(rt);
        // Outside any runtime now: the Drop reads the clock and reports.
        let _ = &mut b;
        drop(b);
        assert_eq!(adm.stats().body_deadline, 0);
        // The open stretch is capped and tiny here: not slow, not an error.
        assert_eq!(adm.stats().slow_body, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_open_wait_is_charged_at_most_the_slow_wait() {
        let (mut b, adm) = timed(&[(600_000, Some(1))], BodyLimits::default());
        let pending = std::future::poll_fn(|cx| {
            Poll::Ready(http_body::Body::poll_frame(Pin::new(&mut b), cx).is_pending())
        })
        .await;
        assert!(pending);
        tokio::time::advance(Duration::from_secs(4)).await;
        drop(b);
        // Capped at exactly slow_wait, which is not over it.
        assert_eq!(adm.stats().slow_body, 0);
        assert_eq!(adm.top_body_wait_summary(), "u(3s)");
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_then_one_long_stall_is_slow_whatever_the_rate_credit() {
        // 9 MiB at once (about 144 s of rate credit), then the last byte after
        // 140 s: inside the cut-off deadline, and under 3 s + credit in total.
        let (mut b, adm) = timed(
            &[(0, Some(9 << 20)), (140_000, Some(1)), (0, None)],
            BodyLimits::default(),
        );
        assert_eq!(drain_body(&mut b).await, 0);
        drop(b);
        let st = adm.stats();
        assert_eq!((st.body_deadline, st.slow_body), (0, 1));
        assert_eq!(points(&adm, "u"), SLOW_WEIGHT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_then_a_trickle_under_the_single_stall_limit_is_slow() {
        // 9 MiB at once, then 1 byte every 2.9 s for 140 s (48 stretches).
        let steps: Vec<_> = [(0, Some(9 << 20))]
            .into_iter()
            .chain((0..48).map(|_| (2900, Some(1))))
            .chain([(0, None)])
            .collect();
        let (mut b, adm) = timed(&steps, BodyLimits::default());
        assert_eq!(drain_body(&mut b).await, 0);
        drop(b);
        let st = adm.stats();
        assert_eq!((st.body_deadline, st.slow_body), (0, 1));
        assert_eq!(points(&adm, "u"), SLOW_WEIGHT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_steady_upload_at_the_minimum_rate_is_not_slow() {
        // 64 KiB every second for 30 s: exactly the 64 KiB/s floor.
        let steps: Vec<_> = (0..30)
            .map(|_| (1000, Some(64 * 1024)))
            .chain([(0, None)])
            .collect();
        let (mut b, adm) = timed(&steps, BodyLimits::default());
        assert_eq!(drain_body(&mut b).await, 0);
        drop(b);
        assert_eq!(adm.stats().slow_body, 0);
        assert_eq!(points(&adm, "u"), 0);
    }

    #[tokio::test]
    async fn a_client_that_stalls_then_disconnects_over_a_real_socket_is_slow() {
        use tokio::io::AsyncWriteExt;
        let (base, adm, _gate) = body_app(BodyLimits {
            slow_wait: Duration::from_millis(300),
            ..BodyLimits::default()
        })
        .await;
        let mut conn = tokio::net::TcpStream::connect(base.trim_start_matches("http://"))
            .await
            .unwrap();
        conn.write_all(
            b"POST /api/body HTTP/1.1\r\nHost: x\r\nx-user: sock-slow\r\n\
              Content-Length: 75000\r\n\r\n0123456789",
        )
        .await
        .unwrap();
        // Over the 1 s accounting floor and the 300 ms slow limit.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        drop(conn);
        adm.idle().await;
        let st = adm.stats();
        assert_eq!((st.slow_body, st.body_deadline), (1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_large_steady_upload_with_short_gaps_is_not_slow() {
        // 20 chunks of 200 KiB, 2 s apart (100 KiB/s): 40 s waited in all.
        let steps: Vec<_> = (0..20)
            .map(|_| (2000, Some(200 * 1024)))
            .chain([(0, None)])
            .collect();
        let (mut b, adm) = timed(&steps, BodyLimits::default());
        assert_eq!(drain_body(&mut b).await, 0);
        drop(b);
        let st = adm.stats();
        assert_eq!((st.body_deadline, st.slow_body), (0, 0));
        assert_eq!(points(&adm, "u"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_handler_pause_mid_body_past_the_deadline_is_not_cut_off() {
        let (mut b, adm) = timed(
            &[(0, Some(10)), (100, Some(10)), (0, None)],
            limits(1000, 1000, 1000),
        );
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        // The handler does other work: far past first byte + grace + credit.
        tokio::time::sleep(Duration::from_secs(30)).await;
        // The inner body is then Pending for 100 ms: the pause is credited.
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        assert!(next_frame(&mut b).await.is_none());
        drop(b);
        let st = adm.stats();
        assert_eq!((st.body_deadline, st.slow_body), (0, 0));
        assert_eq!(points(&adm, "u"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_handler_pause_does_not_excuse_a_client_stall_afterwards() {
        let (mut b, adm) = timed(
            &[(0, Some(10)), (1_000_000, Some(1))],
            limits(1000, 1000, 1000),
        );
        assert!(next_frame(&mut b).await.unwrap().is_ok());
        tokio::time::sleep(Duration::from_secs(30)).await;
        // Pending past the grace (1 s plus the credited 30 s): cut off.
        assert!(next_frame(&mut b).await.unwrap().is_err());
        drop(b);
        assert_eq!(adm.stats().body_deadline, 1);
        assert_eq!(points(&adm, "u"), CUT_WEIGHT);
    }

    #[tokio::test(start_paused = true)]
    async fn configured_body_limits_change_the_cut_off() {
        let cfg = crate::config::AdmissionBody::from_vars(Some("2"), None, None).unwrap();
        let adm = Admission::configured(cfg.into());
        let inner = Body::new(Script {
            frames: vec![],
            then_end: false,
        });
        let mut b = DeadlineBody::new(inner, adm.clone(), "cfg-user".into());
        let t0 = tokio::time::Instant::now();
        // Still alive at 1.9 s ...
        let early = tokio::time::timeout(Duration::from_millis(1900), next_frame(&mut b)).await;
        assert!(early.is_err(), "cut off before the 2 s first-byte limit");
        // ... and cut off at 2 s.
        assert!(next_frame(&mut b).await.unwrap().is_err());
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_secs(2) && waited < Duration::from_millis(2100),
            "{waited:?}"
        );
        drop(b);
        assert_eq!(adm.stats().body_deadline, 1);
    }

    #[test]
    fn refusal_lines_carry_reason_user_pending_and_summaries() {
        let (cap, _g) = crate::api::audit_capture::capture();
        let gauge: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(7)));
        let adm = Admission::with_backlog(gauge);
        let _held = adm.try_admit("holder").unwrap();
        for (why, reason, crowded) in [
            (Refusal::User, "user_cap", false),
            (Refusal::Global, "global_cap", true),
            (Refusal::Backlog, "audit_backlog", true),
        ] {
            cap.clear();
            adm.refuse("bad\nuser", why);
            let l = cap.take_one();
            assert_eq!(l["reason"], reason);
            assert_eq!(l["user_id"], "bad?user", "{reason}");
            assert_eq!(l["suppressed"], "0", "{reason}");
            assert_eq!(l["pending"], "7", "{reason}");
            assert_eq!(!l["top_holders"].is_empty(), crowded, "{reason}");
            assert_eq!(!l["top_body_wait"].is_empty(), crowded, "{reason}");
            if crowded {
                assert_eq!(l["top_holders"], "holder(1)");
            }
        }
    }

    #[test]
    fn cut_off_slow_and_block_lines_are_logged_with_ids_only() {
        let (cap, _g) = crate::api::audit_capture::capture();
        let adm = Admission::with_body(BodyLimits::default());
        cap.clear();
        adm.note_cut_off("cut\nuser");
        let l = cap.take_one();
        assert_eq!(
            l["message"],
            "request body cut off: too slow while holding an admission permit"
        );
        assert_eq!(
            (l["user_id"].as_str(), l["suppressed"].as_str()),
            ("cut?user", "0")
        );

        cap.clear();
        let wait = BodyWait {
            waited: Duration::from_secs(5),
            longest: Duration::from_secs(4),
            excess: Duration::from_secs(4),
        };
        adm.note_body_done("slow\nuser", wait, 100, false);
        let l = cap.take_one();
        assert!(l["message"].starts_with("request body slow"), "{l:?}");
        assert_eq!(l["user_id"], "slow?user");
        assert_eq!(
            (l["waited_ms"].as_str(), l["bytes"].as_str()),
            ("5000", "100")
        );
        assert_eq!(l["suppressed"], "0");

        cap.clear();
        let strict = Admission::with_body(BodyLimits {
            penalty_cuts: 1,
            ..BodyLimits::default()
        });
        strict.note_cut_off_at("block\nuser", Instant::now());
        let l = cap.take_one();
        assert_eq!(l["reason"], "body_penalty_block");
        assert_eq!(l["user_id"], "block?user");
        assert_eq!(l["points"], CUT_WEIGHT.to_string());
        assert_eq!(l["until_ms"], "30000");
    }

    #[test]
    fn backlog_latch_changes_are_logged_once_each() {
        let (cap, _g) = crate::api::audit_capture::capture();
        let gauge: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(0)));
        let adm = Admission::with_backlog(gauge);
        cap.clear();
        gauge.store(AUDIT_BACKLOG_HIGH, Ordering::Relaxed);
        assert_eq!(adm.try_admit("u").unwrap_err(), Refusal::Backlog);
        let l = cap.take_one();
        assert!(l["message"].contains("backlog high"), "{l:?}");
        assert_eq!(l["pending"], AUDIT_BACKLOG_HIGH.to_string());
        // Still high: no second line, and the drain is the only new one.
        assert_eq!(adm.try_admit("u").unwrap_err(), Refusal::Backlog);
        gauge.store(AUDIT_BACKLOG_LOW, Ordering::Relaxed);
        assert!(adm.try_admit("u").is_ok());
        let l = cap.take_one();
        assert!(l["message"].contains("backlog drained"), "{l:?}");
        assert_eq!(l["pending"], AUDIT_BACKLOG_LOW.to_string());
    }

    /// Axum 0.7 cannot list a router's routes, so this scans the sources.
    /// The path-to-handler binding is by construction in the `audited_reads!`
    /// macro (`audit.rs`) and is NOT checked by this scan. The handlers are
    /// private to `audit.rs`, so the macro router is the only possible mount.
    /// This scan covers handler-to-`record_audit_read`: the `audit.read`
    /// action is recorded only in `audit.rs`, from exactly the handlers in
    /// `AUDITED_READ_HANDLERS`. `audited_read_routes_match_the_real_router` in
    /// `main.rs` is the authoritative behavioural check.
    #[test]
    fn audit_read_is_recorded_only_by_the_listed_handlers() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
        let literal = ["\"audit", ".read\""].concat();
        let mut audit_src = String::new();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let src = std::fs::read_to_string(&path).unwrap();
            match name.as_str() {
                // This file names the literal in its own docs and tests.
                "admission.rs" => {}
                "audit.rs" => audit_src = src,
                _ => assert!(
                    !src.contains(&literal),
                    "{name} records audit.read: add its route to the audited_reads! table \
                     (api/audit.rs) so it is admitted, and update this test"
                ),
            }
        }
        // The macro in `audit.rs` has a `#[cfg(test)]` of its own, so cut at
        // the sentinel comment placed before the test module.
        const SENTINEL: &str = "// --- end of non-test code (tripwire boundary) ---";
        let prod = audit_src
            .split_once(SENTINEL)
            .unwrap_or_else(|| panic!("audit.rs lost its `{SENTINEL}` comment"))
            .0
            .to_string();

        // Handlers (top-level fns) that call record_audit_read.
        let mut current = String::new();
        let mut callers = std::collections::BTreeSet::new();
        for line in prod.lines() {
            let t = line.trim_start();
            if line.len() == t.len() {
                for pre in ["pub async fn ", "pub fn ", "async fn ", "fn "] {
                    if let Some(rest) = t.strip_prefix(pre) {
                        current = rest
                            .split(['(', '<'])
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        break;
                    }
                }
            }
            if line.contains("record_audit_read(") && !line.contains("fn record_audit_read(") {
                callers.insert(current.clone());
            }
        }
        let listed: std::collections::BTreeSet<String> = crate::api::audit::AUDITED_READ_HANDLERS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            callers, listed,
            "handlers calling record_audit_read must equal the audited_reads! table"
        );

        // The literal occurs once, inside record_audit_read.
        assert_eq!(
            prod.matches(&literal).count(),
            1,
            "audit.read literal count"
        );
        let def = prod
            .find("fn record_audit_read(")
            .expect("record_audit_read");
        let lit = prod.find(&literal).unwrap();
        assert!(
            lit > def,
            "audit.read literal must be inside record_audit_read"
        );
        // The fn ends at the first `}` in column 0 after its definition.
        let end = prod[def..].find("\n}\n").map_or(prod.len(), |e| def + e);
        assert!(
            lit < end,
            "audit.read literal must be inside record_audit_read"
        );
    }

    fn slow_at(a: &Admission, user: &str, t: Instant) {
        a.note_body_done_at(user, Duration::from_secs(5), 0, false, t);
    }

    #[test]
    fn six_slow_bodies_in_the_window_block_and_five_do_not() {
        let a = Admission::with_body(BodyLimits::default());
        let t0 = Instant::now();
        for i in 0..5u64 {
            slow_at(&a, "u1", t0 + Duration::from_secs(i));
        }
        let t = t0 + Duration::from_secs(6);
        assert!(a.try_admit_at("u1", false, t).is_ok());
        slow_at(&a, "u1", t0 + Duration::from_secs(5));
        assert_eq!(a.try_admit_at("u1", false, t).unwrap_err(), Refusal::User);
        assert!(a.try_admit_at("u2", false, t).is_ok());
        assert_eq!(a.stats().slow_body, 6);
        assert!(a
            .try_admit_at("u1", false, t0 + Duration::from_secs(5 + 30))
            .is_ok());
    }

    #[test]
    fn two_cut_offs_plus_two_slow_bodies_block_and_three_cut_offs_still_do() {
        let a = Admission::with_body(BodyLimits::default());
        let t0 = Instant::now();
        a.note_cut_off_at("u1", t0);
        a.note_cut_off_at("u1", t0 + Duration::from_secs(1));
        slow_at(&a, "u1", t0 + Duration::from_secs(2));
        let t = t0 + Duration::from_secs(3);
        assert!(a.try_admit_at("u1", false, t).is_ok());
        slow_at(&a, "u1", t0 + Duration::from_secs(3));
        assert_eq!(a.try_admit_at("u1", false, t).unwrap_err(), Refusal::User);
        let b = Admission::with_body(BodyLimits::default());
        for i in 0..3 {
            b.note_cut_off_at("u1", t0 + Duration::from_secs(i));
        }
        assert_eq!(b.try_admit_at("u1", false, t).unwrap_err(), Refusal::User);
    }

    #[test]
    fn a_zero_slow_weight_counts_and_logs_but_never_blocks() {
        let a = Admission::with_body(BodyLimits {
            slow_weight: 0,
            ..BodyLimits::default()
        });
        let t0 = Instant::now();
        for i in 0..20u64 {
            slow_at(&a, "u1", t0 + Duration::from_secs(i));
        }
        assert_eq!(a.stats().slow_body, 20);
        assert_eq!(points(&a, "u1"), 0);
        assert!(a
            .try_admit_at("u1", false, t0 + Duration::from_secs(21))
            .is_ok());
    }

    #[test]
    fn body_wait_is_summed_per_window_and_listed_top_first() {
        let a = Admission::with_body(BodyLimits::default());
        let now = Instant::now();
        a.note_body_done_at("bob", Duration::from_secs(20), 1 << 30, false, now);
        a.note_body_done_at("alice", Duration::from_secs(30), 1 << 30, false, now);
        a.note_body_done_at("bob", Duration::from_secs(20), 1 << 30, false, now);
        // Under the note floor: not recorded.
        a.note_body_done_at("carol", Duration::from_millis(900), 0, false, now);
        assert_eq!(a.top_body_wait_summary(), "bob(40s), alice(30s)");
    }

    fn gauge() -> &'static AtomicU32 {
        Box::leak(Box::new(AtomicU32::new(0)))
    }

    #[test]
    fn the_audit_backlog_refuses_non_admins_at_the_mark_with_hysteresis() {
        let g = gauge();
        let a = Admission::with_backlog(g);
        g.store(AUDIT_BACKLOG_HIGH - 1, Ordering::Relaxed);
        assert!(a.try_admit("u1").is_ok());
        g.store(AUDIT_BACKLOG_HIGH, Ordering::Relaxed);
        assert_eq!(a.try_admit("u2").unwrap_err(), Refusal::Backlog);
        // An admin is spared between the marks.
        assert!(a.try_admit_as("admin-x", true).is_ok());
        // Still refused while draining above the low mark.
        g.store(AUDIT_BACKLOG_LOW + 1, Ordering::Relaxed);
        assert_eq!(a.try_admit("u2").unwrap_err(), Refusal::Backlog);
        g.store(AUDIT_BACKLOG_LOW, Ordering::Relaxed);
        assert!(a.try_admit("u2").is_ok());
        // Cleared: back above low but below high is admitted again.
        g.store(AUDIT_BACKLOG_HIGH - 1, Ordering::Relaxed);
        assert!(a.try_admit("u3").is_ok());
    }

    #[test]
    fn the_audit_backlog_refuses_admins_at_the_admin_mark() {
        let g = gauge();
        let a = Admission::with_backlog(g);
        g.store(AUDIT_BACKLOG_ADMIN_HIGH - 1, Ordering::Relaxed);
        assert!(a.try_admit_as("admin-x", true).is_ok());
        g.store(AUDIT_BACKLOG_ADMIN_HIGH, Ordering::Relaxed);
        assert_eq!(
            a.try_admit_as("admin-y", true).unwrap_err(),
            Refusal::Backlog
        );
    }

    #[test]
    fn the_user_cap_wins_over_the_backlog_and_backlog_refusals_are_counted() {
        let g = gauge();
        let a = Admission::with_backlog(g);
        let _held: Vec<_> = (0..MAX_USER_IN_FLIGHT)
            .map(|_| a.try_admit("u1").unwrap())
            .collect();
        g.store(AUDIT_BACKLOG_HIGH, Ordering::Relaxed);
        assert_eq!(a.try_admit("u1").unwrap_err(), Refusal::User);
        let why = a.try_admit("u2").unwrap_err();
        assert_eq!(why, Refusal::Backlog);
        a.refuse("u2", why);
        assert_eq!(a.stats().refused_backlog, 1);
        assert_eq!(a.stats().refused_user, 0);
    }

    #[test]
    fn the_third_refusal_reason_is_throttled_independently() {
        let mut t = WarnThrottle::default();
        let t0 = Instant::now();
        assert_eq!(t.decide(Refusal::Global, t0), Some(0));
        assert_eq!(t.decide(Refusal::Global, t0), None);
        assert_eq!(t.decide(Refusal::Backlog, t0), Some(0));
        assert_eq!(t.decide(Refusal::Backlog, t0), None);
        assert_eq!(t.decide(Refusal::Backlog, t0), None);
        assert_eq!(t.decide(Refusal::Backlog, t0 + WARN_INTERVAL), Some(2));
        assert_eq!(t.decide(Refusal::Global, t0 + WARN_INTERVAL), Some(1));
    }

    #[test]
    fn the_production_admission_reads_the_global_audit_queue_gauge() {
        assert!(std::ptr::eq(
            Admission::new().backlog,
            crate::db_audit::admitted_pending_gauge()
        ));
        assert!(!std::ptr::eq(
            Admission::with_caps(3, 2).backlog,
            crate::db_audit::admitted_pending_gauge()
        ));
    }

    #[tokio::test]
    async fn a_backlog_is_refused_503_with_retry_after_5_before_the_handler() {
        let g = gauge();
        let (mut state, _dir) = lazy_state();
        state.admission = Admission::with_backlog(g);
        let adm = state.admission.clone();
        let (gate, _entered) = Gate::new();
        let base = serve(app(state, gate.clone())).await;
        g.store(AUDIT_BACKLOG_HIGH, Ordering::Relaxed);
        expect_refused_after(
            call(&base, "POST", "/api/gate", "backlog-u").await,
            503,
            "server busy",
            "5",
        )
        .await;
        assert_eq!(gate.entered.load(Ordering::SeqCst), 0);
        // An audited read is refused too; an unadmitted read is not.
        expect_refused_after(
            call(&base, "GET", "/api/audit/events", "backlog-u").await,
            503,
            "server busy",
            "5",
        )
        .await;
        assert_eq!(
            call(&base, "GET", "/api/probe", "backlog-u").await.status(),
            200
        );
        assert_eq!(adm.stats().refused_backlog, 2);
        // An admin is spared below the admin mark.
        assert_eq!(
            call(&base, "POST", "/api/fast", "admin-backlog")
                .await
                .status(),
            200
        );
        g.store(0, Ordering::Relaxed);
        assert_eq!(
            call(&base, "POST", "/api/fast", "backlog-u").await.status(),
            200
        );
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
                    let s = crate::crypto::tls::http_client_builder()
                        .build()
                        .unwrap()
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
    async fn a_viewer_post_is_403_with_one_authz_denied_row(pool: PgPool) {
        seed_user(&pool, "viewer-d").await;
        let (state, _dir) = app_state(pool.clone());
        let adm = state.admission.clone();
        let router = with_user(protected_stack(
            Router::new().route("/api/save", post(|| async { StatusCode::OK })),
            &state,
        ))
        .with_state(state);
        let base = serve_app(router).await;
        let r = crate::crypto::tls::http_client_builder()
            .build()
            .unwrap()
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

    async fn viewer_router(state: AppState) -> String {
        let router = with_user(protected_stack(
            Router::new().route("/api/save", post(|| async { StatusCode::OK })),
            &state,
        ))
        .with_state(state);
        serve_app(router).await
    }

    async fn viewer_post(base: &str) -> reqwest::Response {
        crate::crypto::tls::http_client_builder()
            .build()
            .unwrap()
            .post(format!("{base}/api/save"))
            .header("x-user", "viewer-d")
            .send()
            .await
            .unwrap()
    }

    async fn audit_rows(pool: &PgPool) -> Vec<(String, String)> {
        sqlx::query_as("SELECT action, outcome FROM audit_events")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    // #175 decision: no Playwright spec for the viewer-at-cap 403. A viewer's
    // refused mutation takes no permit and always gets 403, which
    // `e2e/51-viewer-role.spec.js` covers; the at-the-cap variant needs permits
    // held in flight, which a browser cannot arrange without a new test hook
    // (new attack surface), and the UI shows nothing cap-specific.
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_viewer_over_its_cap_is_403_with_an_authz_denied_row(pool: PgPool) {
        seed_user(&pool, "viewer-d").await;
        let (state, _dir) = app_state(pool.clone());
        let adm = state.admission.clone();
        let _held: Vec<_> = (0..MAX_USER_IN_FLIGHT)
            .map(|_| adm.try_admit("viewer-d").unwrap())
            .collect();
        let base = viewer_router(state).await;
        // Not a 429: a viewer's refused mutation takes no permit.
        assert_eq!(viewer_post(&base).await.status().as_u16(), 403);
        crate::db_audit::drain().await;
        assert_eq!(
            audit_rows(&pool).await,
            [("authz.denied".to_string(), "denied".to_string())]
        );
        let st = adm.stats();
        assert_eq!(st.refused_user, 0);
        assert_eq!(st.in_flight, MAX_USER_IN_FLIGHT);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_viewer_mutation_under_audit_backlog_is_403_not_503(pool: PgPool) {
        seed_user(&pool, "viewer-d").await;
        let (mut state, _dir) = app_state(pool.clone());
        let gauge: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(AUDIT_BACKLOG_HIGH)));
        state.admission = Admission::with_backlog(gauge);
        let adm = state.admission.clone();
        let base = viewer_router(state).await;
        assert_eq!(viewer_post(&base).await.status().as_u16(), 403);
        crate::db_audit::drain().await;
        assert_eq!(
            audit_rows(&pool).await,
            [("authz.denied".to_string(), "denied".to_string())]
        );
        assert_eq!(adm.stats().refused_backlog, 0);
    }
}
