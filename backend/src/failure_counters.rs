//! In-process failure counters: status on `GET /api/health`, numbers on the
//! admin-only `GET /api/admin/failure-counters`.
//!
//! Two failure classes are otherwise only visible as `tracing::error!` lines:
//! swallowed audit-write failures (`db_audit::record_or_log`) and failed
//! `login_notice_acks` prune ticks. Each is counted here so a monitor can see
//! `degraded` without scraping logs (AU-5, SI-4).
//!
//! Monitors should alert on the rate of change of `writeFailures` (admin
//! endpoint `GET /api/admin/failure-counters`), not only on the public
//! `degraded` status, which self-clears after a quiet window. The
//! authoritative AU-5 signal across replicas and restarts is the
//! `failed to write audit event` error log line (target `audit`), which needs
//! a log-based alert; these counters are an in-process aid, not AU-5(1)/(2).
//!
//! Counting rule for audit writes (`db_audit`): each write runs as a detached
//! task, so it is counted whether or not the request that submitted it is
//! cancelled. A success is a success even when it lands after the caller's
//! 5 s wait (it also adds one to `lateWrites` on the admin endpoint). A
//! failure is a confirmed error after the retry, the 30 s hard cap, or a
//! write shed because 64 were already pending. The hard cap is the one case
//! where a counted failure may still have committed. Alert on the rate of
//! `writeFailures`; `lateWrites` and `pendingWrites` are early warnings of a
//! slow pool and do not degrade the public status.
//!
//! Sustained-failure signal: alongside the counts, each counter keeps a
//! 32-minute bitmap of which clock minutes saw at least one failure
//! (`RecentFailures`, per replica, minute granularity). `/api/health` turns
//! it into `checks.audit.sustained` (failures in several distinct minutes of
//! the last 15), so an outage reads differently from one isolated failure.
//! `record_success` does not clear the bitmap, so the signal decays on its
//! own. Limit: a replica that audits fewer than 3 writes in distinct minutes
//! per 15 minutes cannot reach `sustained`; the log alert covers that case.
//!
//! Limits: counters are per replica and reset on restart; the `tracing` lines
//! remain the cross-replica signal. A process crash or kill inside the
//! shutdown drain window loses pending writes uncounted. Atomics use
//! `Relaxed` ordering and a snapshot does not read the fields atomically as a
//! group, so concurrent updates may be observed slightly out of step with each
//! other.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use chrono::{DateTime, Utc};

/// Counts failures and tracks the current failure streak. Timestamps are unix
/// seconds, `0` meaning never.
#[derive(Debug)]
pub struct FailureCounter {
    total: AtomicU64,
    consecutive: AtomicU64,
    last_failure_unix: AtomicI64,
    last_success_unix: AtomicI64,
    /// High 32 bits: unix minute of the latest failure. Low 32 bits: bit `i`
    /// set means a failure in minute `latest - i`. `0` means never.
    recent: AtomicU64,
}

/// Which recent clock minutes saw a failure (see [`FailureCounter`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecentFailures {
    last_minute: u32,
    bits: u32,
}

impl RecentFailures {
    /// Distinct minutes with a failure among the last `window_minutes`
    /// (the current minute counts as age 0). At most 32.
    pub fn minutes_within(&self, now: DateTime<Utc>, window_minutes: u32) -> u32 {
        debug_assert!(window_minutes <= 32);
        let now_minute = u32::try_from(now.timestamp().max(0) / 60).unwrap_or(u32::MAX);
        let age = now_minute.saturating_sub(self.last_minute);
        if age >= window_minutes {
            return 0;
        }
        let span = window_minutes - age;
        let mask = if span >= 32 {
            u32::MAX
        } else {
            (1u32 << span) - 1
        };
        (self.bits & mask).count_ones()
    }

    #[cfg(test)]
    pub(crate) fn from_minutes_ago(now: DateTime<Utc>, ago: &[u32]) -> Self {
        let now_minute = u32::try_from(now.timestamp() / 60).unwrap_or(0);
        let mut r = Self {
            last_minute: now_minute,
            bits: 0,
        };
        let newest = ago.iter().copied().min().unwrap_or(0);
        r.last_minute = now_minute.saturating_sub(newest);
        for a in ago {
            r.bits |= 1u32 << (a - newest);
        }
        r
    }
}

/// A point-in-time copy of a [`FailureCounter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureSnapshot {
    pub total: u64,
    pub consecutive: u64,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub recent: RecentFailures,
}

impl FailureCounter {
    pub const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            consecutive: AtomicU64::new(0),
            last_failure_unix: AtomicI64::new(0),
            last_success_unix: AtomicI64::new(0),
            recent: AtomicU64::new(0),
        }
    }

    /// Count one failure; returns the new consecutive-failure count.
    pub fn record_failure(&self) -> u64 {
        self.record_failure_at(Utc::now().timestamp())
    }

    /// [`record_failure`](Self::record_failure) at an explicit unix time.
    pub(crate) fn record_failure_at(&self, unix: i64) -> u64 {
        let minute = u32::try_from(unix.max(0) / 60).unwrap_or(u32::MAX);
        // Lossless under concurrency: retry the compare-exchange on contention.
        let mut old = self.recent.load(Ordering::Relaxed);
        loop {
            let new = if old == 0 {
                (u64::from(minute) << 32) | 1
            } else {
                let old_minute = (old >> 32) as u32;
                let old_bits = old as u32;
                // A backwards clock step counts as the same minute.
                let shift = minute.saturating_sub(old_minute);
                let bits = if shift >= 32 {
                    1
                } else {
                    (old_bits << shift) | 1
                };
                (u64::from(minute.max(old_minute)) << 32) | u64::from(bits)
            };
            match self
                .recent
                .compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(cur) => old = cur,
            }
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        self.last_failure_unix.store(unix, Ordering::Relaxed);
        self.consecutive.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Reset the failure streak (the cumulative total and the recent-minutes
    /// bitmap are kept); returns the streak that was reset.
    pub fn record_success(&self) -> u64 {
        let streak = self.consecutive.swap(0, Ordering::Relaxed);
        self.last_success_unix
            .store(Utc::now().timestamp(), Ordering::Relaxed);
        streak
    }

    pub fn snapshot(&self) -> FailureSnapshot {
        let at = |v: &AtomicI64| match v.load(Ordering::Relaxed) {
            0 => None,
            t => DateTime::from_timestamp(t, 0),
        };
        FailureSnapshot {
            total: self.total.load(Ordering::Relaxed),
            consecutive: self.consecutive.load(Ordering::Relaxed),
            last_failure_at: at(&self.last_failure_unix),
            last_success_at: at(&self.last_success_unix),
            recent: {
                let v = self.recent.load(Ordering::Relaxed);
                RecentFailures {
                    last_minute: (v >> 32) as u32,
                    bits: v as u32,
                }
            },
        }
    }
}

impl Default for FailureCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Swallowed audit-write failures (`db_audit::record_or_log`).
pub static AUDIT_WRITES: FailureCounter = FailureCounter::new();
/// Failed background `prune_acks` ticks.
pub static ACK_PRUNE: FailureCounter = FailureCounter::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_snapshot_is_empty() {
        let s = FailureCounter::new().snapshot();
        assert_eq!((s.total, s.consecutive), (0, 0));
        assert!(s.last_failure_at.is_none() && s.last_success_at.is_none());
    }

    #[test]
    fn failure_counts_and_stamps() {
        let c = FailureCounter::new();
        assert_eq!(c.record_failure(), 1);
        assert_eq!(c.record_failure(), 2);
        let s = c.snapshot();
        assert_eq!((s.total, s.consecutive), (2, 2));
        assert!(s.last_failure_at.is_some());
        assert!(s.last_success_at.is_none());
    }

    #[test]
    fn success_resets_streak_not_total() {
        let c = FailureCounter::new();
        c.record_failure();
        c.record_success();
        let s = c.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 0));
        assert!(s.last_success_at.is_some());
        assert_eq!(c.record_failure(), 1);
    }

    const T0: i64 = 1_700_000_040; // a minute boundary

    fn at_min(unix: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(unix, 0).unwrap()
    }

    #[test]
    fn fresh_counter_has_no_recent_minutes() {
        let s = FailureCounter::new().snapshot();
        assert_eq!(s.recent.minutes_within(at_min(T0), 15), 0);
    }

    #[test]
    fn failures_in_one_minute_count_once() {
        let c = FailureCounter::new();
        for i in 0..20 {
            c.record_failure_at(T0 + i % 60);
        }
        assert_eq!(c.snapshot().recent.minutes_within(at_min(T0 + 30), 15), 1);
    }

    #[test]
    fn distinct_minutes_count_and_old_ones_drop_out() {
        let c = FailureCounter::new();
        for m in [0, 2, 5] {
            c.record_failure_at(T0 + m * 60);
        }
        let r = c.snapshot().recent;
        assert_eq!(r.minutes_within(at_min(T0 + 5 * 60), 15), 3);
        // 11 minutes later the first failure (age 16) is outside the window.
        assert_eq!(r.minutes_within(at_min(T0 + 16 * 60), 15), 2);
        assert_eq!(r.minutes_within(at_min(T0 + 20 * 60), 15), 0);
    }

    #[test]
    fn a_long_gap_resets_the_bitmap() {
        let c = FailureCounter::new();
        c.record_failure_at(T0);
        c.record_failure_at(T0 + 60);
        c.record_failure_at(T0 + 40 * 60);
        assert_eq!(
            c.snapshot().recent.minutes_within(at_min(T0 + 40 * 60), 15),
            1
        );
    }

    #[test]
    fn a_backwards_clock_step_keeps_bits() {
        let c = FailureCounter::new();
        c.record_failure_at(T0);
        c.record_failure_at(T0 + 5 * 60);
        c.record_failure_at(T0 + 2 * 60); // clock stepped back
        let r = c.snapshot().recent;
        // The minute-0 bit from before the step survives; the stepped-back
        // failure folds into the latest minute.
        assert_eq!(r.minutes_within(at_min(T0 + 5 * 60), 15), 2);
        assert_eq!(r.last_minute, (T0 / 60) as u32 + 5);
        assert_eq!(r.bits, 0b10_0001);
        assert_eq!(c.snapshot().total, 3);
    }

    #[test]
    fn concurrent_failures_are_counted_and_keep_the_bitmap_intact() {
        // Seed an earlier minute, then race failures into two later minutes.
        // A late older minute folds into the newest one by design, so the
        // number of distinct minutes depends on arrival order: 3 when
        // T0+60 lands before T0+120, otherwise 2 (T0 and T0+120). Either
        // way the seeded bit must survive, the newest minute must win and
        // every failure must be counted. A non-atomic load/store version
        // could lose the seed's shift or the newest minute under this race.
        let c = FailureCounter::new();
        c.record_failure_at(T0);
        let threads: u64 = 16;
        std::thread::scope(|s| {
            for i in 0..threads {
                let c = &c;
                s.spawn(move || {
                    c.record_failure_at(T0 + 60 * (1 + (i % 2) as i64));
                });
            }
        });
        let snap = c.snapshot();
        assert_eq!(snap.total, threads + 1);
        assert_eq!(snap.recent.last_minute, (T0 / 60) as u32 + 2);
        let n = snap.recent.minutes_within(at_min(T0 + 120), 15);
        assert!((2..=3).contains(&n), "{n}");
    }

    #[test]
    fn record_success_returns_streak_and_keeps_recent() {
        let c = FailureCounter::new();
        for i in 0..3 {
            c.record_failure_at(T0 + i * 60);
        }
        let before = c.snapshot().recent;
        assert_eq!(c.record_success(), 3);
        assert_eq!(c.record_success(), 0);
        let after = c.snapshot();
        assert_eq!(after.recent, before);
        assert_eq!(after.recent.minutes_within(at_min(T0 + 2 * 60), 15), 3);
        assert_eq!(after.total, 3);
    }
}
