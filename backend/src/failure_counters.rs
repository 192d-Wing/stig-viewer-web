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
//! Limits: counters are per replica and reset on restart; the `tracing` lines
//! remain the cross-replica signal. A loss that never reaches the counting
//! point (task aborted before `record_or_log` finishes, process crash) is not
//! counted. Atomics use `Relaxed` ordering and a snapshot does not read the
//! fields atomically as a group, so concurrent updates may be observed
//! slightly out of step with each other.

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
}

/// A point-in-time copy of a [`FailureCounter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureSnapshot {
    pub total: u64,
    pub consecutive: u64,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
}

impl FailureCounter {
    pub const fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            consecutive: AtomicU64::new(0),
            last_failure_unix: AtomicI64::new(0),
            last_success_unix: AtomicI64::new(0),
        }
    }

    /// Count one failure; returns the new consecutive-failure count.
    pub fn record_failure(&self) -> u64 {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.last_failure_unix
            .store(Utc::now().timestamp(), Ordering::Relaxed);
        self.consecutive.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Reset the failure streak; the cumulative total is kept.
    pub fn record_success(&self) {
        self.consecutive.store(0, Ordering::Relaxed);
        self.last_success_unix
            .store(Utc::now().timestamp(), Ordering::Relaxed);
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
}
