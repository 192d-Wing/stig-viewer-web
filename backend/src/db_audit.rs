//! Durable request-level audit events (`audit_events`).
//!
//! `rule_audit` records one row per rule field change; this table records the
//! request that caused them, including requests that were rejected (400) or
//! denied (403). `detail` holds only counts, status values, reason codes and
//! (truncated) rule ids; never finding details, comments or other free text
//! from the request. The one exception is `auth.notice_ack`, whose `detail`
//! carries the sanitized, truncated User-Agent and client IP of the acknowledgement.
//!
//! System-originated events (no acting user, for example a scheduled DISA
//! download stopped by its size cap) are written by [`record_system_or_log`]
//! with a NULL `user_id` and `user_role = 'system'` (migration 045).
//!
//! Writes are detached tasks in a bounded queue ([`WriteQueue`]): at most
//! [`MAX_PENDING_WRITES`] (64) pending in all, of which at most
//! [`MAX_DENIED_PENDING`] (16) `denied`/`rejected` events (so a flood of
//! denials sheds first and cannot take slots from other events, which always
//! have at least 48), and at most [`MAX_USER_DENIED_PENDING`] (4)
//! denied/rejected ones per acting user. Other events have no per-user cap, so
//! a user inside the request rate limit never loses its own events. A write over
//! a cap is shed and no row is written. There are three shed reasons: total
//! and shared denied share (each logs an ids-only error line and counts as a
//! failure), and the per-user denied sub-cap (counted in `shedWrites` only, not
//! a failure: one account must not be able to degrade public health; it logs at
//! most once per user per 60 s, with a summary of the held-back ones). Every
//! shed counts in `shedWrites`. Alert on the `shedWrites` rate and the
//! failure counter, not only on the public status. The caps are checked and
//! taken atomically.
//!
//! The queue is sized against the admission cap (`api::admission`), not
//! against the rate limit: each admitted request holds a permit until its
//! writes finish and awaits its writes one at a time, so admitted requests
//! never have more than `MAX_IN_FLIGHT` (32) non-restricted writes pending,
//! leaving 16 of the 48 non-restricted slots for permit-less events
//! (`auth.notice_ack`, system events). A compile-time assert in `admission`
//! pins this arithmetic; it holds for any `RATE_LIMIT_BURST` and for admins,
//! who bypass the rate limiter. It is strict only while the pool is healthy:
//! a stalled insert lets one request leave late writes behind under its permit.
//! When that happens the count of non-restricted pending writes
//! ([`WriteQueue::open_gauge`]) climbs past the healthy bound, and `admission`
//! refuses new requests (503) at a high-water mark until it drains. That damps
//! the stacking; it does not bound it, since requests already admitted can
//! still leave writes behind.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::Notify;

use crate::api::request_ctx::RequestCtx;
use crate::failure_counters::{FailureCounter, AUDIT_WRITES};

/// At most this many rejected rules are listed in an event's `detail`.
pub const MAX_REJECTED_LISTED: usize = 100;

pub struct NewAuditEvent<'a> {
    pub user_id: &'a str,
    /// "rules.bulk_status" | "rules.bulk_import" | "checklist.save" | "checklist.create" | "auth.notice_ack"
    /// | "catalog.upload" | "catalog.import_library" | "catalog.import_library_entry" | "catalog.sync"
    pub action: &'static str,
    /// "ok" | "partial" | "denied" | "rejected"
    pub outcome: &'static str,
    pub asset_id: Option<&'a str>,
    pub checklist_id: Option<&'a str>,
    pub stig_id: Option<&'a str>,
    pub detail: Value,
    /// Request context (source IP, request id, role). `None` outside a request.
    pub ctx: Option<&'a RequestCtx>,
}

/// An event with no acting user: written with a NULL `user_id` and
/// `user_role = 'system'`. Never collapsed with earlier rows.
pub struct NewSystemEvent<'a> {
    pub action: &'static str,
    /// "ok" | "partial" | "denied" | "rejected"
    pub outcome: &'static str,
    pub stig_id: Option<&'a str>,
    pub detail: Value,
}

/// Declare an audit maintenance mode (`retention`, `restore`, `migration` or `test`) for the
/// rest of this transaction; the guard triggers from migration 040 permit the
/// matching mutation of `rule_audit` / `audit_events` only while it is set.
/// `test` works only in a database flagged with `stig.audit_allow_test_mode=on`
/// (migration 043, see [`allow_test_maintenance`]); elsewhere the guard raises 42501.
pub(crate) async fn set_maintenance(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mode: &str,
) -> Result<()> {
    sqlx::query("SELECT set_config('stig.audit_maintenance', $1, true)")
        .bind(mode)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Advisory-lock key serializing audit retention sweeps (ASCII "stigretn").
/// Per-database; never reuse this value for another lock.
pub(crate) const RETENTION_SWEEP_LOCK: i64 = 0x7374_6967_7265_746E;

/// Advisory-lock key serializing the owner step of `migrate` (ASCII "stigownr").
/// Session-level, per-database; never reuse this value for another lock.
pub(crate) const OWNER_STEP_LOCK: i64 = 0x7374_6967_6F77_6E72;

/// How long a sweep waits for the lock before failing (and retrying on the
/// next scheduler tick).
pub(crate) const RETENTION_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// Take the retention-sweep lock, waiting up to `wait` if another sweep holds
/// it, then failing with "another retention sweep holds the lock". The lock
/// is transaction-level: it is released when the returned transaction is
/// committed, rolled back or dropped, or its connection is lost.
///
/// Pool budget: the holder pins one of the pool's connections for the whole
/// sweep and every waiter pins one more while it waits. Never let many sweeps
/// queue in one process (relevant if a "run now" endpoint is ever added).
pub(crate) async fn lock_retention_sweep(
    pool: &PgPool,
    wait: std::time::Duration,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL idle_in_transaction_session_timeout = 0")
        .execute(&mut *tx)
        .await?;
    // SET cannot take bind parameters; the value is an integer we format.
    let ms = wait.as_millis().max(1);
    sqlx::query(&format!("SET LOCAL lock_timeout = {ms}"))
        .execute(&mut *tx)
        .await?;
    if let Err(e) = sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock($1)")
        .bind(RETENTION_SWEEP_LOCK)
        .execute(&mut *tx)
        .await
    {
        let timed_out = e
            .as_database_error()
            .and_then(|d| d.code())
            .is_some_and(|c| c == "55P03");
        if timed_out {
            anyhow::bail!("another retention sweep holds the lock");
        }
        return Err(e.into());
    }
    Ok(tx)
}

/// Confirm the lock transaction's connection is still alive.
pub(crate) async fn retention_lock_alive(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<()> {
    use anyhow::Context;
    sqlx::query("SELECT 1")
        .execute(&mut **tx)
        .await
        .context("retention sweep lock lost")?;
    Ok(())
}

/// True when the current database carries `stig.audit_allow_test_mode=on`.
/// Same predicate as the guard trigger in migration 043; keep them in sync.
const TEST_FLAG_SQL: &str = "SELECT EXISTS ( \
    SELECT 1 FROM pg_catalog.pg_db_role_setting s \
    JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase \
    WHERE d.datname = pg_catalog.current_database() \
      AND s.setrole = 0 \
      AND 'stig.audit_allow_test_mode=on' = ANY (s.setconfig))";

pub(crate) async fn test_maintenance_allowed(pool: &PgPool) -> Result<bool> {
    Ok(sqlx::query_scalar(TEST_FLAG_SQL).fetch_one(pool).await?)
}

/// Flag the current database for audit `test` maintenance mode. Idempotent.
/// Needs a superuser or `GRANT SET ON PARAMETER stig.audit_allow_test_mode`.
///
/// Concurrent callers race on the same `pg_db_role_setting` row: the loser's
/// `ALTER DATABASE` fails ("tuple concurrently updated", or a unique violation
/// when the first-ever set races) even though the flag ends up set. Both are
/// raised only after the winner committed, so on failure the flag is checked
/// again and, if present, the call succeeds. The error text is never matched;
/// without the flag the original error (e.g. 42501) stands. The owner step
/// also takes [`OWNER_STEP_LOCK`], so this covers callers outside that lock.
pub(crate) async fn allow_test_maintenance(pool: &PgPool) -> Result<()> {
    use anyhow::Context;
    if test_maintenance_allowed(pool).await? {
        return Ok(());
    }
    let set = sqlx::query(
        "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET stig.audit_allow_test_mode = %L', \
         current_database(), 'on'); END $$",
    )
    .execute(pool)
    .await;
    match set {
        Ok(_) => Ok(()),
        Err(e) => {
            if test_maintenance_allowed(pool).await.unwrap_or(false) {
                tracing::debug!("audit test mode was set concurrently: {e}");
                return Ok(());
            }
            Err(e).context("enabling audit test mode needs a superuser or GRANT SET ON PARAMETER stig.audit_allow_test_mode (PostgreSQL 15+; older versions: superuser only)")
        }
    }
}

/// Startup rule for the flag: a flagged database with test routes off is
/// refused in every environment (fail closed).
pub(crate) fn check_test_maintenance_flag(test_routes: bool, flag_set: bool) -> Result<()> {
    if !test_routes && flag_set {
        anyhow::bail!(
            "refusing to start: database has stig.audit_allow_test_mode=on, which permits \
             audit UPDATE/TRUNCATE, but test routes are off; run ALTER DATABASE <db> RESET \
             stig.audit_allow_test_mode, or set STIG_ENABLE_TEST_ROUTES again"
        );
    }
    Ok(())
}

/// Startup policy. Test routes on: flag the database (needs a superuser or
/// GRANT SET ON PARAMETER stig.audit_allow_test_mode, PostgreSQL 15+). Test
/// routes off: refuse to start if the database is flagged. No audit_events row
/// is written: startup has no request and no acting user (system events go
/// through [`record_system_or_log`], which needs the migrated schema).
pub(crate) async fn apply_test_maintenance_policy(
    pool: &PgPool,
    enable_test_routes: bool,
) -> Result<()> {
    if enable_test_routes {
        allow_test_maintenance(pool).await?;
        tracing::warn!(
            "audit `test` maintenance mode is ENABLED for this database (test routes are on)"
        );
        return Ok(());
    }
    check_test_maintenance_flag(false, test_maintenance_allowed(pool).await?)
}

/// How long a caller waits for its audit write (see [`submit`]), so a busy
/// pool cannot hold the response for the pool's acquire timeout. The write
/// itself is not cancelled at this point; it continues up to
/// [`HARD_WRITE_TIMEOUT`].
pub const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Upper bound on the write task itself (both attempts of [`record_or_log`]).
/// Longer than the shutdown drain (`SHUTDOWN_DRAIN` in `main.rs`) on purpose.
pub const HARD_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Longest id kept in an id column (and its log lines).
pub const MAX_ID_CHARS: usize = 128;

/// An id column value made safe to store and log: at most [`MAX_ID_CHARS`]
/// characters, anything outside ASCII alphanumerics and `._:-` replaced by `?`.
pub fn bound_id(id: &str) -> String {
    sanitize(id, MAX_ID_CHARS)
}

fn sanitize(id: &str, max: usize) -> String {
    id.chars()
        .take(max)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-') {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// The three id columns, bounded once and used for both insert attempts and
/// the log lines so no caller can store or print an unbounded value.
struct BoundedIds {
    asset_id: Option<String>,
    checklist_id: Option<String>,
    stig_id: Option<String>,
}

fn bounded(ev: &NewAuditEvent<'_>) -> BoundedIds {
    BoundedIds {
        asset_id: ev.asset_id.map(bound_id),
        checklist_id: ev.checklist_id.map(bound_id),
        stig_id: ev.stig_id.map(bound_id),
    }
}

async fn insert<'e, E: sqlx::PgExecutor<'e>>(
    pool: E,
    ev: &NewAuditEvent<'_>,
    ids: &BoundedIds,
    detail: &Value,
) -> Result<()> {
    insert_row(
        pool,
        Some(ev.user_id),
        ev.ctx.map(|c| bound_id(&c.role)),
        ev,
        ids,
        detail,
    )
    .await
}

async fn insert_row<'e, E: sqlx::PgExecutor<'e>>(
    pool: E,
    user_id: Option<&str>,
    role: Option<String>,
    ev: &NewAuditEvent<'_>,
    ids: &BoundedIds,
    detail: &Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_events (user_id, action, outcome, asset_id, checklist_id, stig_id, detail, \
                                  source_ip, request_id, user_role) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)",
    )
    .bind(user_id)
    .bind(ev.action)
    .bind(ev.outcome)
    .bind(&ids.asset_id)
    .bind(&ids.checklist_id)
    .bind(&ids.stig_id)
    .bind(detail.to_string())
    .bind(ev.ctx.and_then(|c| c.source_ip.as_deref()))
    .bind(ev.ctx.map(|c| c.request_id.as_str()))
    .bind(role)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert an event on an open transaction, so it commits or rolls back with
/// the caller's work. Unlike [`record_or_log`] a failure is returned.
pub(crate) async fn record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ev: &NewAuditEvent<'_>,
) -> Result<()> {
    if let Some(ctx) = ev.ctx {
        ctx.audited
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    insert(&mut **tx, ev, &bounded(ev), &ev.detail).await
}

/// Identical `denied`/`rejected` events from the same user within this many
/// seconds of the first one are collapsed into it (see [`collapse`]).
pub const COLLAPSE_WINDOW_SECS: i64 = 300;

/// Collapse a repeated denied/rejected event into the newest matching row
/// (same user, action, outcome, the three id columns, the `detail` without its client-derived counters (`requested`, `distinct`),
/// `source_ip` and `user_role`) whose first occurrence is within [`COLLAPSE_WINDOW_SECS`]. Only
/// `repeat_count` and `last_occurred_at` change; the row keeps the first
/// request's `request_id`, `source_ip` and `detail`. Returns whether a row was
/// updated. Not atomic with the insert that follows a miss: a race yields at
/// worst two rows.
async fn collapse<'e, E: sqlx::PgExecutor<'e>>(
    pool: E,
    ev: &NewAuditEvent<'_>,
    ids: &BoundedIds,
    detail: &Value,
) -> Result<bool> {
    if !matches!(ev.outcome, "denied" | "rejected") {
        return Ok(false);
    }
    let n = sqlx::query(
        "UPDATE audit_events SET repeat_count = repeat_count + 1, \
             last_occurred_at = GREATEST(NOW(), COALESCE(last_occurred_at, occurred_at)) \
         WHERE id = (SELECT id FROM audit_events \
                      WHERE user_id = $1 AND action = $2 AND outcome = $3 \
                        AND asset_id IS NOT DISTINCT FROM $4::text \
                        AND checklist_id IS NOT DISTINCT FROM $5::text \
                        AND stig_id IS NOT DISTINCT FROM $6::text \
                        AND (detail - 'requested' - 'distinct') IS NOT DISTINCT FROM ($7::jsonb - 'requested' - 'distinct') \
                        AND source_ip IS NOT DISTINCT FROM $9::text \
                        AND user_role IS NOT DISTINCT FROM $10::text \
                        AND occurred_at > NOW() - make_interval(secs => $8) \
                      ORDER BY id DESC LIMIT 1)",
    )
    .bind(ev.user_id)
    .bind(ev.action)
    .bind(ev.outcome)
    .bind(&ids.asset_id)
    .bind(&ids.checklist_id)
    .bind(&ids.stig_id)
    .bind(detail.to_string())
    .bind(COLLAPSE_WINDOW_SECS as f64)
    .bind(ev.ctx.and_then(|c| c.source_ip.as_deref()))
    .bind(ev.ctx.map(|c| bound_id(&c.role)))
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

#[cfg(test)]
async fn record_event(pool: &PgPool, ev: &NewAuditEvent<'_>) -> Result<()> {
    insert(pool, ev, &bounded(ev), &ev.detail).await
}

/// Record an event without ever failing the caller. The request has already
/// been (or is about to be) answered, so a failure is logged at error level,
/// counted in [`AUDIT_WRITES`] (status on `/api/health`, numbers on the
/// admin-only `/api/admin/failure-counters`) and otherwise ignored; the
/// structured `tracing` line stays as the fallback record. If the insert
/// fails, it is retried once with the same columns and a constant `detail`, so no content-dependent failure (for example text that
/// jsonb rejects) can suppress the row. Both attempts share [`HARD_WRITE_TIMEOUT`].
///
/// The write runs as a detached task (see [`submit`]): the caller waits for it
/// at most [`WRITE_TIMEOUT`], and dropping the caller's future (client abort)
/// does not cancel it.
pub async fn record_or_log(pool: &PgPool, ev: NewAuditEvent<'_>) {
    record_counted(pool, ev, &GLOBAL_QUEUE, LIMITS).await;
}

/// [`record_or_log`], reporting whether the write was queued or shed.
pub async fn record_or_log_reporting(pool: &PgPool, ev: NewAuditEvent<'_>) -> Submission {
    record_counted(pool, ev, &GLOBAL_QUEUE, LIMITS).await
}

/// Record a system-originated event without ever failing the caller. Same
/// guarantees as [`record_or_log`] (detached, caller waits at most
/// [`WRITE_TIMEOUT`], counted in [`AUDIT_WRITES`], retried once without
/// `detail`) but no collapse: every call is its own row.
pub async fn record_system_or_log(pool: &PgPool, ev: NewSystemEvent<'_>) {
    record_system_counted(pool, ev, &GLOBAL_QUEUE, LIMITS).await;
}

/// Pending audit writes at which new ones are shed instead of queued. The
/// pool has at most 5 connections (`db.rs`); waiting tasks hold none.
pub const MAX_PENDING_WRITES: u32 = 64;

/// Of those, how many may be `denied`/`rejected` events (a client can trigger
/// these at will, so they shed first).
pub const MAX_DENIED_PENDING: u32 = 16;

/// `denied`/`rejected` pending writes allowed for one acting user, so one
/// account cannot fill the shared denied share alone. Other events have no
/// per-user cap here: `api::admission` bounds them (per-user 4, global 32
/// in-flight requests).
pub const MAX_USER_DENIED_PENDING: u32 = 4;

/// Bound on getting a pooled connection inside the write task, shorter than
/// the pool's own 30 s acquire timeout so slots recycle faster when the pool
/// is stalled.
pub const ACQUIRE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The two waits around one detached audit write.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// How long the caller waits for the write before moving on.
    pub wait: std::time::Duration,
    /// Hard cap on the write itself (both attempts).
    pub hard: std::time::Duration,
}

const LIMITS: Limits = Limits {
    wait: WRITE_TIMEOUT,
    hard: HARD_WRITE_TIMEOUT,
};

/// Bounded queue of detached audit writes plus the counters they report to.
///
/// Counting rule: a write that succeeds is a success, even when it finishes
/// after the caller stopped waiting (that also adds one to `late`). A failure
/// is a confirmed error after the retry, the [`HARD_WRITE_TIMEOUT`] cap, or a
/// write shed because [`MAX_PENDING_WRITES`] were already pending. A caller
/// that is dropped has no effect on counting.
pub(crate) struct WriteQueue {
    counter: &'static FailureCounter,
    late: AtomicU64,
    shed: AtomicU64,
    state: Mutex<QueueState>,
    idle: Notify,
    cap: u32,
    denied_cap: u32,
    user_denied_cap: u32,
    /// Pending non-restricted writes. Written only under the `state` lock (so
    /// it always matches `pending - denied`), read without it by admission.
    open_pending: AtomicU32,
}

/// Pending counts, all behind one lock so a reservation checks and takes
/// every cap atomically.
struct QueueState {
    pending: u32,
    denied: u32,
    /// Pending counts per acting user (at most `cap` entries).
    users: Vec<UserPending>,
    /// Log rate-limit state for per-user restricted sheds (at most
    /// [`MAX_NOISY_USERS`] entries, oldest evicted).
    noisy: Vec<Noisy>,
}

struct UserPending {
    user: String,
    /// Restricted (`denied`/`rejected`) pending writes (against `user_denied_cap`).
    denied: u32,
}

struct Noisy {
    user: String,
    last_logged: std::time::Instant,
    suppressed: u64,
}

/// Distinct users tracked for shed-log rate limiting.
const MAX_NOISY_USERS: usize = 32;

/// At most one per-user restricted-shed log line per user per this window.
const SHED_LOG_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

impl QueueState {
    /// Decide whether a per-user restricted shed for `user` logs now.
    /// `Some(n)`: log it, plus a summary if `n > 0` earlier ones were held
    /// back. `None`: held back (counted in the next summary).
    fn shed_log_due(&mut self, user: &str, now: std::time::Instant) -> Option<u64> {
        if let Some(n) = self.noisy.iter_mut().find(|n| n.user == user) {
            if now.saturating_duration_since(n.last_logged) >= SHED_LOG_WINDOW {
                n.last_logged = now;
                return Some(std::mem::take(&mut n.suppressed));
            }
            n.suppressed += 1;
            return None;
        }
        if self.noisy.len() >= MAX_NOISY_USERS {
            self.noisy.remove(0);
        }
        self.noisy.push(Noisy {
            user: user.to_owned(),
            last_logged: now,
            suppressed: 0,
        });
        Some(0)
    }
}

/// What a write counts against besides the total.
struct Reserve {
    /// Acting user; `None` (system events) is exempt from the per-user denied sub-cap.
    user: Option<String>,
    /// A `denied`/`rejected` event, subject to the denied sub-cap.
    restricted: bool,
}

/// Why a write was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShedReason {
    Full,
    DeniedShare,
    /// One user's `denied`/`rejected` sub-cap: counted in `shedWrites` only.
    UserDenied,
}

/// Result of [`record_or_log_reporting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submission {
    /// The write was queued (it may still have failed or be late).
    Submitted,
    /// A cap was hit: no row will be written.
    Shed,
}

/// One pending slot in a [`WriteQueue`], released when dropped.
struct Slot {
    queue: &'static WriteQueue,
    reserve: Reserve,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let empty = {
            let mut st = self.queue.lock();
            st.pending = st.pending.saturating_sub(1);
            if self.reserve.restricted {
                st.denied = st.denied.saturating_sub(1);
            } else {
                self.queue.open_pending.fetch_sub(1, Ordering::Relaxed);
            }
            if let (true, Some(u)) = (self.reserve.restricted, &self.reserve.user) {
                if let Some(i) = st.users.iter().position(|e| &e.user == u) {
                    let e = &mut st.users[i];
                    e.denied = e.denied.saturating_sub(1);
                    if e.denied == 0 {
                        st.users.swap_remove(i);
                    }
                }
            }
            st.pending == 0
        };
        if empty {
            self.queue.idle.notify_waiters();
        }
    }
}

impl WriteQueue {
    pub(crate) const fn new(
        counter: &'static FailureCounter,
        cap: u32,
        denied_cap: u32,
        user_denied_cap: u32,
    ) -> Self {
        Self {
            counter,
            late: AtomicU64::new(0),
            shed: AtomicU64::new(0),
            state: Mutex::new(QueueState {
                pending: 0,
                denied: 0,
                users: Vec::new(),
                noisy: Vec::new(),
            }),
            idle: Notify::const_new(),
            cap,
            denied_cap,
            user_denied_cap,
            open_pending: AtomicU32::new(0),
        }
    }

    /// Pending non-restricted writes, readable without the queue lock.
    pub(crate) fn open_gauge(&'static self) -> &'static AtomicU32 {
        &self.open_pending
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        // Plain counters: a poisoned lock still holds a usable state.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reserve a slot against every cap at once, or say which cap refused.
    fn try_reserve(&'static self, reserve: Reserve) -> Result<Slot, ShedReason> {
        let mut st = self.lock();
        if st.pending >= self.cap {
            return Err(ShedReason::Full);
        }
        if reserve.restricted {
            let idx = reserve
                .user
                .as_ref()
                .and_then(|u| st.users.iter().position(|e| &e.user == u));
            let denied = idx.map_or(0, |i| st.users[i].denied);
            // Own sub-cap first: a flooder is shed by its own limit.
            if reserve.user.is_some() && denied >= self.user_denied_cap {
                return Err(ShedReason::UserDenied);
            }
            if st.denied >= self.denied_cap {
                return Err(ShedReason::DeniedShare);
            }
            if let Some(u) = &reserve.user {
                match idx {
                    Some(i) => st.users[i].denied += 1,
                    None => st.users.push(UserPending {
                        user: u.clone(),
                        denied: 1,
                    }),
                }
            }
        }
        st.pending += 1;
        if reserve.restricted {
            st.denied += 1;
        } else {
            self.open_pending.fetch_add(1, Ordering::Relaxed);
        }
        drop(st);
        Ok(Slot {
            queue: self,
            reserve,
        })
    }

    /// Writes that finished successfully after their caller stopped waiting.
    pub(crate) fn late_writes(&self) -> u64 {
        self.late.load(Ordering::Relaxed)
    }

    /// Writes refused because a cap was reached (also counted as failures).
    pub(crate) fn shed_writes(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }

    /// Writes submitted and not yet finished.
    pub(crate) fn pending(&self) -> u64 {
        u64::from(self.lock().pending)
    }

    /// Wait until no write is pending (and so every one has been counted).
    /// Does not block new submissions.
    pub(crate) async fn drain(&self) {
        loop {
            // Register before checking so a wakeup between the two is kept.
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.pending() == 0 {
                return;
            }
            notified.await;
        }
    }
}

static GLOBAL_QUEUE: WriteQueue = WriteQueue::new(
    &AUDIT_WRITES,
    MAX_PENDING_WRITES,
    MAX_DENIED_PENDING,
    MAX_USER_DENIED_PENDING,
);

/// The process-wide queue's count of pending non-restricted writes.
pub(crate) fn open_pending_gauge() -> &'static AtomicU32 {
    GLOBAL_QUEUE.open_gauge()
}

/// Wait for every pending audit write (shutdown).
pub(crate) async fn drain() {
    GLOBAL_QUEUE.drain().await;
}

/// `(lateWrites, pendingWrites, shedWrites)` of the process-wide audit queue.
pub(crate) fn write_stats() -> (u64, u64, u64) {
    (
        GLOBAL_QUEUE.late_writes(),
        GLOBAL_QUEUE.pending(),
        GLOBAL_QUEUE.shed_writes(),
    )
}

/// Owned, ids-only fields for log lines about one write.
struct LogFields {
    user_id: String,
    action: &'static str,
    outcome: &'static str,
    request_id: Option<String>,
    asset_id: Option<String>,
    checklist_id: Option<String>,
    stig_id: Option<String>,
}

impl LogFields {
    fn error(&self, what: &str) {
        tracing::error!(
            target: "audit",
            user_id = self.user_id,
            action = self.action,
            outcome = self.outcome,
            request_id = self.request_id.as_deref(),
            asset_id = self.asset_id.as_deref(),
            checklist_id = self.checklist_id.as_deref(),
            stig_id = self.stig_id.as_deref(),
            "failed to write audit event: {what}"
        );
    }

    fn warn_late(&self, wait: std::time::Duration) {
        tracing::warn!(
            target: "audit",
            user_id = self.user_id,
            action = self.action,
            outcome = self.outcome,
            request_id = self.request_id.as_deref(),
            asset_id = self.asset_id.as_deref(),
            checklist_id = self.checklist_id.as_deref(),
            stig_id = self.stig_id.as_deref(),
            "audit write still pending after {wait:?}; caller stopped waiting, write continues"
        );
    }
}

/// Counts a failure if the write task ends without reporting an outcome
/// (a panic, or the runtime shutting down).
struct OutcomeGuard<'a> {
    queue: &'static WriteQueue,
    log: &'a LogFields,
    reported: bool,
}

impl Drop for OutcomeGuard<'_> {
    fn drop(&mut self) {
        if !self.reported {
            self.log.error("write task ended without finishing");
            self.queue.counter.record_failure();
        }
    }
}

/// Run `write` as a task the caller cannot cancel, and wait for it at most
/// `limits.wait`.
///
/// Before its first await this function either sheds (a cap is reached: ids-only error line, one failure and one
/// shed counted, nothing spawned) or spawns the task. So `x.await` and `timeout_at(deadline, x)` both
/// submit the write on first poll, before any point where the caller can be
/// cancelled. Callers must poll it at least once; dropping the future after
/// that leaves the write running.
///
/// Outcomes, all counted by the task itself: success is a success (plus
/// `late` when the caller had already stopped waiting); an error after the
/// retry, or `limits.hard` elapsing, is a failure. The hard cap is the one
/// case where a counted failure may still have committed: dropping an
/// in-flight sqlx query does not cancel it server-side.
///
/// Ordering: a late row is stamped by the database at insert, so
/// `occurred_at` can trail the request by up to the hard cap.
async fn submit(
    queue: &'static WriteQueue,
    limits: Limits,
    log: LogFields,
    reserve: Reserve,
    write: impl std::future::Future<Output = Result<()>> + Send + 'static,
) -> Submission {
    let slot = match queue.try_reserve(reserve) {
        Ok(slot) => slot,
        Err(why) => {
            let what = match why {
                ShedReason::Full => format!("shed: {} audit writes already pending", queue.cap),
                ShedReason::DeniedShare => format!(
                    "shed: {} denied/rejected audit writes already pending",
                    queue.denied_cap
                ),
                ShedReason::UserDenied => format!(
                    "shed: {} denied/rejected audit writes already pending for this user",
                    queue.user_denied_cap
                ),
            };
            queue.shed.fetch_add(1, Ordering::Relaxed);
            if why == ShedReason::UserDenied {
                // Not a failure: one account must not be able to degrade
                // public health. Logs are rate limited per user.
                let due = queue
                    .lock()
                    .shed_log_due(&log.user_id, std::time::Instant::now());
                if let Some(held_back) = due {
                    log.error(&what);
                    if held_back > 0 {
                        tracing::error!(
                            target: "audit",
                            user_id = log.user_id,
                            "{held_back} more denied events shed for this user"
                        );
                    }
                }
            } else {
                log.error(&what);
                queue.counter.record_failure();
            }
            return Submission::Shed;
        }
    };
    let log = Arc::new(log);
    let task_log = Arc::clone(&log);
    // Exactly one side decides on-time vs late, by compare_exchange from WAITING.
    let state = Arc::new(AtomicU8::new(WAITING));
    let task_state = Arc::clone(&state);
    let hard = limits.hard;
    let handle = tokio::spawn(async move {
        let _slot = slot;
        let mut guard = OutcomeGuard {
            queue,
            log: &task_log,
            reported: false,
        };
        match tokio::time::timeout(hard, write).await {
            Ok(Ok(())) => {
                queue.counter.record_success();
                if task_state
                    .compare_exchange(WAITING, ON_TIME, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    queue.late.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(Err(e)) => {
                task_log.error(&format!("{e:#}"));
                queue.counter.record_failure();
            }
            Err(_) => {
                task_log.error(&format!("timed out after {hard:?}"));
                queue.counter.record_failure();
            }
        }
        guard.reported = true;
    });
    if tokio::time::timeout(limits.wait, handle).await.is_err()
        && state
            .compare_exchange(WAITING, LATE, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        log.warn_late(limits.wait);
    }
    Submission::Submitted
}

const WAITING: u8 = 0;
const ON_TIME: u8 = 1;
const LATE: u8 = 2;

/// An audit event with every borrowed field owned, so it can move into a
/// detached task.
struct OwnedEvent {
    user_id: String,
    action: &'static str,
    outcome: &'static str,
    asset_id: Option<String>,
    checklist_id: Option<String>,
    stig_id: Option<String>,
    detail: Value,
    ctx: Option<RequestCtx>,
}

impl OwnedEvent {
    fn from(ev: NewAuditEvent<'_>) -> Self {
        Self {
            user_id: ev.user_id.to_owned(),
            action: ev.action,
            outcome: ev.outcome,
            asset_id: ev.asset_id.map(str::to_owned),
            checklist_id: ev.checklist_id.map(str::to_owned),
            stig_id: ev.stig_id.map(str::to_owned),
            detail: ev.detail,
            ctx: ev.ctx.cloned(),
        }
    }
}

/// A pooled connection within [`ACQUIRE_TIMEOUT`].
async fn acquire(pool: &PgPool) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
    match tokio::time::timeout(ACQUIRE_TIMEOUT, pool.acquire()).await {
        Ok(conn) => Ok(conn?),
        Err(_) => anyhow::bail!("no database connection after {ACQUIRE_TIMEOUT:?}"),
    }
}

/// Collapse, insert and the `detailDropped` retry for one user event.
async fn write_user_event(pool: &PgPool, owned: &OwnedEvent, ids: &BoundedIds) -> Result<()> {
    let mut conn = acquire(pool).await?;
    let ev = NewAuditEvent {
        user_id: &owned.user_id,
        action: owned.action,
        outcome: owned.outcome,
        asset_id: owned.asset_id.as_deref(),
        checklist_id: owned.checklist_id.as_deref(),
        stig_id: owned.stig_id.as_deref(),
        detail: Value::Null,
        ctx: owned.ctx.as_ref(),
    };
    match collapse(&mut *conn, &ev, ids, &owned.detail).await {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(target: "audit", action = ev.action, "audit event collapse failed, inserting: {e:#}")
        }
    }
    if let Err(first) = insert(&mut *conn, &ev, ids, &owned.detail).await {
        tracing::warn!(target: "audit", action = ev.action, "audit event insert failed, retrying without detail: {first:#}");
        insert(&mut *conn, &ev, ids, &json!({ "detailDropped": true })).await?;
    }
    Ok(())
}

async fn record_system_counted(
    pool: &PgPool,
    ev: NewSystemEvent<'_>,
    queue: &'static WriteQueue,
    limits: Limits,
) {
    debug_assert!(ev.action.len() <= 64 && ev.outcome.len() <= 64);
    // Reuse the column bounding of user events; user_id is unused.
    let shell = NewAuditEvent {
        user_id: "",
        action: ev.action,
        outcome: ev.outcome,
        asset_id: None,
        checklist_id: None,
        stig_id: ev.stig_id,
        detail: Value::Null,
        ctx: None,
    };
    let ids = bounded(&shell);
    let log = LogFields {
        user_id: "system".to_owned(),
        action: ev.action,
        outcome: ev.outcome,
        request_id: None,
        asset_id: None,
        checklist_id: None,
        stig_id: ids.stig_id.clone(),
    };
    let (action, outcome, detail) = (ev.action, ev.outcome, ev.detail);
    let pool = pool.clone();
    let write = async move {
        let shell = NewAuditEvent {
            user_id: "",
            action,
            outcome,
            asset_id: None,
            checklist_id: None,
            stig_id: ids.stig_id.as_deref(),
            detail: Value::Null,
            ctx: None,
        };
        let role = || Some("system".to_string());
        let mut conn = acquire(&pool).await?;
        if let Err(first) = insert_row(&mut *conn, None, role(), &shell, &ids, &detail).await {
            tracing::warn!(target: "audit", action, "system audit event insert failed, retrying without detail: {first:#}");
            insert_row(
                &mut *conn,
                None,
                role(),
                &shell,
                &ids,
                &json!({ "detailDropped": true }),
            )
            .await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let reserve = Reserve {
        user: None,
        restricted: false,
    };
    submit(queue, limits, log, reserve, write).await;
}

async fn record_counted(
    pool: &PgPool,
    ev: NewAuditEvent<'_>,
    queue: &'static WriteQueue,
    limits: Limits,
) -> Submission {
    debug_assert!(ev.action.len() <= 64 && ev.outcome.len() <= 64);
    // Synchronous, before any await: `authz_audit` reads this flag.
    if let Some(ctx) = ev.ctx {
        ctx.audited
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let ids = bounded(&ev);
    // Ids only in logs: enough to reconstruct the record, no detail content.
    let log = LogFields {
        user_id: ev.user_id.to_owned(),
        action: ev.action,
        outcome: ev.outcome,
        request_id: ev.ctx.map(|c| c.request_id.clone()),
        asset_id: ids.asset_id.clone(),
        checklist_id: ids.checklist_id.clone(),
        stig_id: ids.stig_id.clone(),
    };
    let reserve = Reserve {
        user: Some(ev.user_id.to_owned()),
        restricted: matches!(ev.outcome, "denied" | "rejected"),
    };
    let owned = OwnedEvent::from(ev);
    let pool = pool.clone();
    submit(queue, limits, log, reserve, async move {
        write_user_event(&pool, &owned, &ids).await
    })
    .await
}

/// A rule id made safe for an audit `detail`: truncated to 64 characters and
/// every character outside ASCII alphanumerics and `._:-` replaced by `?`
/// (so NUL, quotes, backslashes and control characters never reach jsonb).
pub fn audit_safe_id(id: &str) -> String {
    sanitize(id, 64)
}

/// `rejected` / `rejectedTruncated` detail fields from per-rule `(rule id,
/// reason)` pairs. Rule ids are passed through [`audit_safe_id`].
pub fn rejected_detail(rejected: &[(String, String)]) -> (Value, bool) {
    let listed: Vec<Value> = rejected
        .iter()
        .take(MAX_REJECTED_LISTED)
        .map(|(rule_id, reason)| json!({ "ruleId": audit_safe_id(rule_id), "reason": reason }))
        .collect();
    (Value::Array(listed), rejected.len() > MAX_REJECTED_LISTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{allow_audit_test_mode, disallow_audit_test_mode, seed_user};
    use std::sync::atomic::AtomicBool;

    /// Run one statement in a transaction with the given audit maintenance mode.
    async fn in_mode(pool: &PgPool, mode: &str, sql: &str) -> Result<()> {
        let mut tx = pool.begin().await?;
        set_maintenance(&mut tx, mode).await?;
        sqlx::query(sql).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    fn is_guard_error(e: &anyhow::Error) -> bool {
        e.downcast_ref::<sqlx::Error>()
            .and_then(|e| e.as_database_error())
            .and_then(|d| d.code())
            .is_some_and(|c| c == "42501")
    }

    async fn seed_both(pool: &PgPool) {
        sqlx::query("INSERT INTO users (id, display_name, email, role, sub, provider) VALUES ('u1', 'u1', '', 'author', 'u1', 'test') ON CONFLICT DO NOTHING")
            .execute(pool).await.unwrap();
        sqlx::query("INSERT INTO rule_audit (user_id, checklist_id, rule_id, field) VALUES ('u1','c','r','status')")
            .execute(pool).await.unwrap();
        sqlx::query("INSERT INTO audit_events (user_id, action, outcome) VALUES ('u1','checklist.save','ok')")
            .execute(pool).await.unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn allow_test_maintenance_survives_concurrent_callers(pool: PgPool) {
        disallow_audit_test_mode(&pool).await;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let pool = pool.clone();
            let barrier = barrier.clone();
            set.spawn(async move {
                barrier.wait().await;
                allow_test_maintenance(&pool).await
            });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap().unwrap();
        }
        assert!(test_maintenance_allowed(&pool).await.unwrap());
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_catalog.pg_db_role_setting s \
             JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase \
             WHERE d.datname = pg_catalog.current_database() AND s.setrole = 0 \
               AND 'stig.audit_allow_test_mode=on' = ANY (s.setconfig)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 1);
        disallow_audit_test_mode(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_rejects_plain_mutation_of_both_tables(pool: PgPool) {
        seed_both(&pool).await;
        for t in ["rule_audit", "audit_events"] {
            for sql in [
                format!("UPDATE {t} SET user_id = user_id"),
                format!("DELETE FROM {t}"),
                format!("TRUNCATE {t}"),
            ] {
                let e = sqlx::query(&sql).execute(&pool).await.unwrap_err();
                assert_eq!(
                    e.as_database_error().and_then(|d| d.code()).as_deref(),
                    Some("42501"),
                    "{sql}"
                );
            }
        }
        let e = sqlx::query("TRUNCATE users CASCADE")
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            e.as_database_error().and_then(|d| d.code()).as_deref(),
            Some("42501")
        );
        let n: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM rule_audit) + (SELECT COUNT(*) FROM audit_events)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 2);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_modes_allow_only_their_operations(pool: PgPool) {
        allow_audit_test_mode(&pool).await;
        seed_both(&pool).await;
        // retention: DELETE only.
        assert!(is_guard_error(
            &in_mode(&pool, "retention", "UPDATE rule_audit SET field = 'x'")
                .await
                .unwrap_err()
        ));
        assert!(is_guard_error(
            &in_mode(&pool, "retention", "TRUNCATE rule_audit")
                .await
                .unwrap_err()
        ));
        // test: UPDATE and TRUNCATE, not DELETE.
        in_mode(&pool, "test", "UPDATE rule_audit SET field = 'x'")
            .await
            .unwrap();
        assert!(is_guard_error(
            &in_mode(&pool, "test", "DELETE FROM rule_audit")
                .await
                .unwrap_err()
        ));
        // An unknown mode permits nothing.
        assert!(is_guard_error(
            &in_mode(&pool, "bogus", "DELETE FROM audit_events")
                .await
                .unwrap_err()
        ));
        in_mode(&pool, "retention", "DELETE FROM rule_audit")
            .await
            .unwrap();
        in_mode(&pool, "retention", "DELETE FROM audit_events")
            .await
            .unwrap();
        // The mode is transaction-local: it does not leak to the next statement.
        let e = sqlx::query("DELETE FROM audit_events").execute(&pool).await;
        assert!(e.is_ok(), "no rows left, so nothing to guard");
        seed_both(&pool).await;
        let e = sqlx::query("DELETE FROM audit_events")
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(e.as_database_error().is_some());
        // restore: TRUNCATE (cascading from users) only; DELETE is rejected.
        seed_both(&pool).await;
        assert!(is_guard_error(
            &in_mode(&pool, "restore", "DELETE FROM rule_audit")
                .await
                .unwrap_err()
        ));
        in_mode(&pool, "restore", "TRUNCATE users CASCADE")
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM rule_audit) + (SELECT COUNT(*) FROM audit_events)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 0);
        seed_both(&pool).await;
        in_mode(&pool, "test", "TRUNCATE users CASCADE")
            .await
            .unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_allows_only_the_collapse_update_without_a_mode(pool: PgPool) {
        allow_audit_test_mode(&pool).await;
        seed_both(&pool).await;
        let code = |e: sqlx::Error| {
            e.as_database_error()
                .and_then(|d| d.code().map(|c| c.to_string()))
        };
        // An `ok` row has no collapse shape.
        let e = sqlx::query(
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW()",
        )
        .execute(&pool)
        .await
        .unwrap_err();
        assert_eq!(code(e).as_deref(), Some("42501"));
        in_mode(&pool, "test", "UPDATE audit_events SET outcome = 'denied'")
            .await
            .unwrap();
        // The collapse shape on a denied row passes without any mode.
        sqlx::query(
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW()",
        )
        .execute(&pool)
        .await
        .unwrap();
        // Rejected: another column too, an outcome change, a jump over 1, a
        // decrease, no change, a past or future or infinite timestamp.
        for sql in [
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW(), action = 'x'",
            "UPDATE audit_events SET outcome = 'ok'",
            "UPDATE audit_events SET repeat_count = repeat_count + 2, last_occurred_at = NOW()",
            "UPDATE audit_events SET repeat_count = 1, last_occurred_at = NOW()",
            "UPDATE audit_events SET repeat_count = repeat_count, last_occurred_at = NOW()",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW() - INTERVAL '1 day'",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NOW() + INTERVAL '1 day'",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = 'infinity'",
            "UPDATE audit_events SET repeat_count = repeat_count + 1, last_occurred_at = NULL",
        ] {
            let e = sqlx::query(sql).execute(&pool).await.unwrap_err();
            assert_eq!(code(e).as_deref(), Some("42501"), "{sql}");
        }
        // rule_audit has no collapse shape.
        let e = sqlx::query("UPDATE rule_audit SET field = 'x'")
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(code(e).as_deref(), Some("42501"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn guard_triggers_are_always_enabled_and_migration_mode_allows_update_only(pool: PgPool) {
        seed_both(&pool).await;
        let enabled: Vec<(String, String)> = sqlx::query_as(
            "SELECT tgname::text, tgenabled::text FROM pg_trigger WHERE tgname LIKE '%\\_guard\\_%' ORDER BY tgname",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(enabled.len(), 4);
        assert!(enabled.iter().all(|(_, e)| e == "A"), "{enabled:?}");
        in_mode(&pool, "migration", "UPDATE rule_audit SET field = 'y'")
            .await
            .unwrap();
        assert!(is_guard_error(
            &in_mode(&pool, "migration", "DELETE FROM rule_audit")
                .await
                .unwrap_err()
        ));
        assert!(is_guard_error(
            &in_mode(&pool, "migration", "TRUNCATE rule_audit")
                .await
                .unwrap_err()
        ));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn collapse_onto_a_row_whose_last_occurrence_is_slightly_in_the_future_still_collapses(
        pool: PgPool,
    ) {
        allow_audit_test_mode(&pool).await;
        seed_user(&pool, "u1").await;
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        in_mode(
            &pool,
            "test",
            "UPDATE audit_events SET last_occurred_at = NOW() + INTERVAL '30 seconds'",
        )
        .await
        .unwrap();
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, 2);
    }

    fn ev(outcome: &'static str, detail: Value) -> NewAuditEvent<'static> {
        NewAuditEvent {
            user_id: "u1",
            action: "checklist.save",
            outcome,
            asset_id: Some("a1"),
            checklist_id: None,
            stig_id: None,
            detail,
            ctx: None,
        }
    }

    #[test]
    fn rejected_detail_caps_the_list() {
        let many: Vec<(String, String)> = (0..150)
            .map(|i| (format!("r{i}"), "why".to_string()))
            .collect();
        let (listed, truncated) = rejected_detail(&many);
        assert_eq!(listed.as_array().unwrap().len(), MAX_REJECTED_LISTED);
        assert!(truncated);
        let (listed, truncated) = rejected_detail(&many[..100]);
        assert_eq!(listed.as_array().unwrap().len(), 100);
        assert!(!truncated);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn records_one_row_per_outcome(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for outcome in ["ok", "partial", "denied", "rejected"] {
            record_event(&pool, &ev(outcome, json!({ "n": 1 })))
                .await
                .unwrap();
        }
        let got: Vec<(String, String, Option<String>)> =
            sqlx::query_as("SELECT outcome, detail->>'n', asset_id FROM audit_events ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        let outcomes: Vec<&str> = got.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(outcomes, ["ok", "partial", "denied", "rejected"]);
        assert!(got
            .iter()
            .all(|r| r.1 == "1" && r.2.as_deref() == Some("a1")));
    }

    async fn rows(pool: &PgPool) -> Vec<(String, i32, bool, Option<String>)> {
        sqlx::query_as(
            "SELECT outcome, repeat_count, last_occurred_at IS NOT NULL, request_id FROM audit_events ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn identical_denials_collapse_and_keep_the_first_context(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for i in 0..5 {
            let mut c = ctx();
            c.request_id = format!("req-{i}");
            let mut e = ev("denied", json!({ "reason": "not_owner" }));
            e.ctx = Some(&c);
            record_or_log(&pool, e).await;
        }
        let got = rows(&pool).await;
        assert_eq!(
            got,
            vec![("denied".to_string(), 5, true, Some("req-0".to_string()))]
        );
        // Only repeat_count and last_occurred_at move: detail is untouched.
        let d: String = sqlx::query_scalar("SELECT detail::text FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&d).unwrap(),
            json!({ "reason": "not_owner" })
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_different_reason_asset_user_or_a_late_repeat_is_a_new_row(pool: PgPool) {
        allow_audit_test_mode(&pool).await;
        seed_user(&pool, "u1").await;
        seed_user(&pool, "u2").await;
        record_or_log(&pool, ev("rejected", json!({ "reason": "a" }))).await;
        record_or_log(&pool, ev("rejected", json!({ "reason": "b" }))).await;
        let mut other_asset = ev("rejected", json!({ "reason": "a" }));
        other_asset.asset_id = Some("a2");
        record_or_log(&pool, other_asset).await;
        let mut other_user = ev("rejected", json!({ "reason": "a" }));
        other_user.user_id = "u2";
        record_or_log(&pool, other_user).await;
        let mut other_action = ev("rejected", json!({ "reason": "a" }));
        other_action.action = "checklist.create";
        record_or_log(&pool, other_action).await;
        assert_eq!(rows(&pool).await.len(), 5);

        // Age the first row past the window: the next identical event inserts.
        in_mode(&pool, "test", "UPDATE audit_events SET occurred_at = NOW() - INTERVAL '6 minutes' WHERE id = (SELECT MIN(id) FROM audit_events)")
            .await
            .unwrap();
        record_or_log(&pool, ev("rejected", json!({ "reason": "a" }))).await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 6);
        assert!(got.iter().all(|r| r.1 == 1));
    }

    fn ctx_with(ip: &str, role: &str) -> RequestCtx {
        RequestCtx {
            source_ip: Some(ip.into()),
            role: role.into(),
            ..ctx()
        }
    }

    async fn denied_authz(pool: &PgPool, c: &RequestCtx, method: &str, route: &str) {
        let mut e = ev("denied", json!({ "method": method, "route": route }));
        e.action = "authz.denied";
        e.asset_id = None;
        e.ctx = Some(c);
        record_or_log(pool, e).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn only_exact_repeats_collapse(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let c = ctx_with("203.0.113.7", "author");
        denied_authz(&pool, &c, "POST", "/api/a").await;
        denied_authz(&pool, &c, "POST", "/api/b").await; // other route
        denied_authz(&pool, &c, "PUT", "/api/a").await; // other method
        denied_authz(&pool, &ctx_with("203.0.113.8", "author"), "POST", "/api/a").await; // other ip
        denied_authz(&pool, &ctx_with("203.0.113.7", "viewer"), "POST", "/api/a").await; // other role
        assert_eq!(rows(&pool).await.len(), 5);
        // An exact repeat with a different request id collapses; the first id is kept.
        let mut again = ctx_with("203.0.113.7", "author");
        again.request_id = "req-other".into();
        denied_authz(&pool, &again, "POST", "/api/a").await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 5);
        assert_eq!(
            got[0],
            ("denied".to_string(), 2, true, Some("req-1".to_string()))
        );
        assert!(got[1..].iter().all(|r| r.1 == 1));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn client_derived_counters_do_not_split_the_key_but_reason_and_dry_run_do(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for n in [1, 50, 9000] {
            record_or_log(
                &pool,
                ev(
                    "rejected",
                    json!({ "reason": "too_many_rules", "requested": n }),
                ),
            )
            .await;
        }
        assert_eq!(rows(&pool).await.len(), 1);
        record_or_log(
            &pool,
            ev("rejected", json!({ "reason": "other", "requested": 1 })),
        )
        .await;
        record_or_log(
            &pool,
            ev(
                "rejected",
                json!({ "reason": "too_many_rules", "dryRun": true, "requested": 1 }),
            ),
        )
        .await;
        record_or_log(
            &pool,
            ev(
                "rejected",
                json!({ "reason": "too_many_rules", "dryRun": false, "requested": 1 }),
            ),
        )
        .await;
        let got = rows(&pool).await;
        assert_eq!(got.len(), 4);
        assert_eq!(got[0].1, 3);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_window_boundary_is_five_minutes(pool: PgPool) {
        allow_audit_test_mode(&pool).await;
        seed_user(&pool, "u1").await;
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        let age = |secs: i32| {
            let pool = pool.clone();
            async move {
                in_mode(&pool, "test", &format!("UPDATE audit_events SET occurred_at = NOW() - make_interval(secs => {secs})")).await
            }
        };
        age(299).await.unwrap(); // 4m59s: still inside
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        assert_eq!(rows(&pool).await.len(), 1);
        age(301).await.unwrap(); // 5m01s: outside
        record_or_log(&pool, ev("denied", json!({ "reason": "a" }))).await;
        assert_eq!(rows(&pool).await.len(), 2);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn ok_and_partial_events_are_never_collapsed(pool: PgPool) {
        seed_user(&pool, "u1").await;
        for outcome in ["ok", "ok", "partial", "partial"] {
            record_or_log(&pool, ev(outcome, json!({ "n": 1 }))).await;
        }
        let got = rows(&pool).await;
        assert_eq!(got.len(), 4);
        assert!(got.iter().all(|r| r.1 == 1 && !r.2));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn record_or_log_swallows_an_insert_failure(pool: PgPool) {
        // No such user: the FK rejects the insert. The helper must not panic
        // or propagate, and nothing is written.
        record_or_log(&pool, ev("ok", json!({}))).await;
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(record_event(&pool, &ev("ok", json!({}))).await.is_err());
        // Wiring check only: `record_or_log` feeds the shared static (other
        // tests add to it too, so no exact value).
        assert!(AUDIT_WRITES.snapshot().total >= 1);
    }

    /// A queue over its own counter, so exact values are not disturbed by
    /// other tests writing to the process-wide one. Usage:
    /// `queue!(C, Q, 64);` declares statics `C` (counter) and `Q` (queue).
    macro_rules! queue {
        ($c:ident, $q:ident, $cap:expr) => {
            queue!($c, $q, $cap, $cap, $cap);
        };
        ($c:ident, $q:ident, $cap:expr, $denied:expr, $udenied:expr) => {
            static $c: FailureCounter = FailureCounter::new();
            static $q: WriteQueue = WriteQueue::new(&$c, $cap, $denied, $udenied);
        };
    }

    /// A reservation for `user`, restricted for denied/rejected events.
    fn rsv(user: &str, restricted: bool) -> Reserve {
        Reserve {
            user: Some(user.to_owned()),
            restricted,
        }
    }

    const SECS: fn(u64) -> std::time::Duration = std::time::Duration::from_secs;
    const MILLIS: fn(u64) -> std::time::Duration = std::time::Duration::from_millis;

    fn log_fields() -> LogFields {
        LogFields {
            user_id: "u1".into(),
            action: "checklist.save",
            outcome: "ok",
            request_id: Some("req-1".into()),
            asset_id: None,
            checklist_id: None,
            stig_id: None,
        }
    }

    /// Poll `f` once and report whether it is still pending. Submission
    /// happens on that first poll.
    async fn poll_once<F: std::future::Future + ?Sized>(f: &mut std::pin::Pin<Box<F>>) -> bool {
        std::future::poll_fn(|cx| std::task::Poll::Ready(f.as_mut().poll(cx).is_pending())).await
    }

    /// A write that waits for `gate`, then returns `result`; `ran` is set
    /// once it has produced its result.
    async fn gated_write(
        gate: tokio::sync::oneshot::Receiver<()>,
        ran: Arc<AtomicBool>,
        ok: bool,
    ) -> Result<()> {
        let _ = gate.await;
        ran.store(true, Ordering::SeqCst);
        if ok {
            Ok(())
        } else {
            Err(anyhow::anyhow!("boom"))
        }
    }

    const LONG: Limits = Limits {
        wait: std::time::Duration::from_secs(60),
        hard: std::time::Duration::from_secs(60),
    };

    #[tokio::test]
    async fn a_cancelled_caller_still_gets_its_write_done_and_counted() {
        queue!(C, Q, 64);
        let (open, gate) = tokio::sync::oneshot::channel();
        let ran = Arc::new(AtomicBool::new(false));
        C.record_failure();
        {
            let mut call = Box::pin(submit(
                &Q,
                LONG,
                log_fields(),
                rsv("u1", false),
                gated_write(gate, ran.clone(), true),
            ));
            assert!(poll_once(&mut call).await, "waiting on the gate");
        } // the caller is dropped before the write finished
        assert_eq!(Q.pending(), 1);
        let _ = open.send(());
        Q.drain().await;
        assert!(ran.load(Ordering::SeqCst));
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 0), "success reset the streak");
        assert!(s.last_success_at.is_some());
        assert_eq!((Q.late_writes(), Q.pending()), (0, 0));
    }

    #[tokio::test]
    async fn a_cancelled_caller_whose_write_fails_is_counted_as_a_failure() {
        queue!(C, Q, 64);
        let (open, gate) = tokio::sync::oneshot::channel();
        let ran = Arc::new(AtomicBool::new(false));
        {
            let mut call = Box::pin(submit(
                &Q,
                LONG,
                log_fields(),
                rsv("u1", false),
                gated_write(gate, ran.clone(), false),
            ));
            assert!(poll_once(&mut call).await);
        }
        let _ = open.send(());
        Q.drain().await;
        assert!(ran.load(Ordering::SeqCst));
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 1));
        assert_eq!(Q.late_writes(), 0);
    }

    #[tokio::test]
    async fn a_write_finishing_after_the_callers_wait_is_a_late_success_not_a_failure() {
        queue!(C, Q, 64);
        let (open, gate) = tokio::sync::oneshot::channel();
        let ran = Arc::new(AtomicBool::new(false));
        let limits = Limits {
            wait: MILLIS(20),
            hard: SECS(5),
        };
        submit(
            &Q,
            limits,
            log_fields(),
            rsv("u1", false),
            gated_write(gate, ran.clone(), true),
        )
        .await;
        // The caller gave up; the write is still in flight and not a failure.
        let s = C.snapshot();
        assert_eq!(s.total, 0);
        assert_eq!(Q.pending(), 1);
        assert!(!ran.load(Ordering::SeqCst));
        let _ = open.send(());
        Q.drain().await;
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (0, 0));
        assert!(s.last_success_at.is_some());
        assert_eq!((Q.late_writes(), Q.pending()), (1, 0));
    }

    #[tokio::test]
    async fn the_hard_cap_counts_a_failure() {
        queue!(C, Q, 64);
        let limits = Limits {
            wait: MILLIS(10),
            hard: MILLIS(30),
        };
        submit(
            &Q,
            limits,
            log_fields(),
            rsv("u1", false),
            std::future::pending::<Result<()>>(),
        )
        .await;
        Q.drain().await;
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 1));
        assert_eq!(Q.late_writes(), 0);
    }

    #[tokio::test]
    async fn a_full_queue_sheds_without_spawning_or_waiting() {
        queue!(C, Q, 1);
        let (open, gate) = tokio::sync::oneshot::channel();
        let ran = Arc::new(AtomicBool::new(false));
        let mut first = Box::pin(submit(
            &Q,
            LONG,
            log_fields(),
            rsv("u1", false),
            gated_write(gate, ran.clone(), true),
        ));
        assert!(poll_once(&mut first).await);
        assert_eq!(Q.pending(), 1);

        let second_ran = Arc::new(AtomicBool::new(false));
        let flag = second_ran.clone();
        // Completes on its first poll: no await on the shed path.
        let mut second = Box::pin(submit(
            &Q,
            LONG,
            log_fields(),
            rsv("u1", false),
            async move {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        ));
        assert!(!poll_once(&mut second).await, "shed returns at once");
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 1));
        assert_eq!((Q.pending(), Q.shed_writes()), (1, 1));

        let _ = open.send(());
        first.await;
        Q.drain().await;
        assert!(
            !second_ran.load(Ordering::SeqCst),
            "the shed write never ran"
        );
        assert!(ran.load(Ordering::SeqCst));
        // The first write's success reset the streak; the shed failure stays in the total.
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 0));
    }

    /// Submit a gated write for `user`; returns its open-gate sender and the
    /// still-pending caller future (polled once, so the slot is taken).
    type BoxCall = std::pin::Pin<Box<dyn std::future::Future<Output = Submission> + Send>>;

    /// Like [`gated_submit`], but `None` when the write was shed.
    async fn try_gated(
        q: &'static WriteQueue,
        user: &str,
        restricted: bool,
    ) -> Option<(tokio::sync::oneshot::Sender<()>, BoxCall)> {
        let (open, gate) = tokio::sync::oneshot::channel();
        let ran = Arc::new(AtomicBool::new(false));
        let mut call: BoxCall = Box::pin(submit(
            q,
            LONG,
            log_fields(),
            rsv(user, restricted),
            gated_write(gate, ran, true),
        ));
        poll_once(&mut call).await.then_some((open, call))
    }

    async fn gated_submit(
        q: &'static WriteQueue,
        user: &str,
        restricted: bool,
    ) -> (tokio::sync::oneshot::Sender<()>, BoxCall) {
        try_gated(q, user, restricted)
            .await
            .expect("queued and waiting")
    }

    #[tokio::test]
    async fn denied_events_shed_at_their_share_and_leave_slots_for_other_events() {
        // 8 slots, 2 of them for denied/rejected, no per-user limit in play.
        queue!(C, Q, 8, 2, 8);
        let mut held = Vec::new();
        for user in ["a", "b"] {
            held.push(gated_submit(&Q, user, true).await);
        }
        assert_eq!(Q.pending(), 2);
        // A third denial is shed at once, though 6 slots are free.
        let mut third = Box::pin(submit(
            &Q,
            LONG,
            log_fields(),
            rsv("c", true),
            std::future::pending::<Result<()>>(),
        ));
        assert!(!poll_once(&mut third).await);
        assert_eq!(
            (Q.pending(), Q.shed_writes(), C.snapshot().total),
            (2, 1, 1)
        );
        // An ok event still gets a slot.
        held.push(gated_submit(&Q, "c", false).await);
        assert_eq!((Q.pending(), Q.shed_writes()), (3, 1));
        for (open, call) in held {
            let _ = open.send(());
            call.await;
        }
        Q.drain().await;
        assert_eq!(Q.pending(), 0);
        // A freed share is usable again.
        held = vec![gated_submit(&Q, "a", true).await];
        for (open, call) in held {
            let _ = open.send(());
            call.await;
        }
        Q.drain().await;
    }

    #[tokio::test]
    async fn one_users_non_restricted_events_are_bounded_only_by_the_total() {
        queue!(C, Q, 64, 16, 4);
        let mut held = Vec::new();
        for i in 0..20 {
            let h = try_gated(&Q, "busy", false).await;
            assert!(h.is_some(), "write {i} must be queued, not shed");
            held.extend(h);
        }
        assert_eq!((Q.shed_writes(), C.snapshot().total), (0, 0));
        // Up to the total, still the same user.
        for i in 20..64 {
            let h = try_gated(&Q, "busy", false).await;
            assert!(h.is_some(), "write {i} must be queued, not shed");
            held.extend(h);
        }
        assert_eq!((Q.pending(), Q.shed_writes()), (64, 0));
        // The 65th sheds as the total and counts a failure.
        assert!(try_gated(&Q, "busy", false).await.is_none());
        assert_eq!((Q.shed_writes(), C.snapshot().total), (1, 1));
        for (open, call) in held {
            let _ = open.send(());
            call.await;
        }
        Q.drain().await;
        assert_eq!(Q.pending(), 0);
    }

    /// True when a write for `user` is shed (returns at once, never runs).
    async fn is_shed(q: &'static WriteQueue, user: &str, restricted: bool) -> bool {
        let mut call = Box::pin(submit(
            q,
            LONG,
            log_fields(),
            rsv(user, restricted),
            std::future::pending::<Result<()>>(),
        ));
        !poll_once(&mut call).await
    }

    #[tokio::test]
    async fn one_users_denials_stop_at_their_subcap_and_leave_room_for_others() {
        // Total 64, denied share 16, per-user denied sub-cap 4.
        queue!(C, Q, 64, 16, 4);
        let mut held = Vec::new();
        // Real flood: queue gated denials until the sub-cap, shed the rest.
        let mut shed = 0;
        for _ in 0..20 {
            match try_gated(&Q, "flood", true).await {
                Some(h) => held.push(h),
                None => shed += 1,
            }
        }
        assert_eq!((held.len(), shed), (4, 16));
        assert_eq!((Q.pending(), Q.shed_writes()), (4, 16));
        // Per-user denied sheds are not failures.
        assert_eq!(C.snapshot().total, 0);
        // Another user's denial still queues, and the flooder's own ok event too.
        let own_ok = try_gated(&Q, "flood", false).await;
        assert!(own_ok.is_some(), "the flooder's own ok event is queued");
        held.extend(own_ok);
        held.push(gated_submit(&Q, "other", true).await);
        assert_eq!(Q.pending(), 6);
        for (open, call) in held {
            let _ = open.send(());
            call.await;
        }
        Q.drain().await;
        assert_eq!((Q.pending(), C.snapshot().total), (0, 0));
        // The shared share still sheds as a failure.
        queue!(C2, Q2, 64, 1, 4);
        let first = gated_submit(&Q2, "a", true).await;
        assert!(is_shed(&Q2, "b", true).await);
        assert_eq!((Q2.shed_writes(), C2.snapshot().total), (1, 1));
        let (open, call) = first;
        let _ = open.send(());
        call.await;
        Q2.drain().await;
    }

    #[test]
    fn shed_logs_are_rate_limited_per_user_and_bounded() {
        let mut st = QueueState {
            pending: 0,
            denied: 0,
            users: Vec::new(),
            noisy: Vec::new(),
        };
        let t0 = std::time::Instant::now();
        assert_eq!(st.shed_log_due("a", t0), Some(0));
        assert_eq!(st.shed_log_due("a", t0 + SECS(1)), None);
        assert_eq!(st.shed_log_due("a", t0 + SECS(59)), None);
        // Another user has its own window.
        assert_eq!(st.shed_log_due("b", t0 + SECS(2)), Some(0));
        // After the window: log again, reporting the two held back.
        assert_eq!(st.shed_log_due("a", t0 + SECS(60)), Some(2));
        assert_eq!(st.shed_log_due("a", t0 + SECS(61)), None);
        // Bounded memory under many distinct users.
        for i in 0..1000 {
            st.shed_log_due(&format!("u{i}"), t0);
        }
        assert!(st.noisy.len() <= MAX_NOISY_USERS);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn record_counted_counts_failure_then_resets_streak_on_success(pool: PgPool) {
        queue!(C, Q, 64);
        record_counted(&pool, ev("ok", json!({})), &Q, LIMITS).await;
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 1));
        seed_user(&pool, "u1").await;
        record_counted(&pool, ev("ok", json!({})), &Q, LIMITS).await;
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 0));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_record_counted_future_dropped_after_one_poll_still_writes_the_row(pool: PgPool) {
        // Current-thread runtime: the spawned write cannot run before the
        // caller yields, so the single poll below returns Pending.
        queue!(C, Q, 64);
        seed_user(&pool, "u1").await;
        {
            let mut call = Box::pin(record_counted(&pool, ev("ok", json!({})), &Q, LIMITS));
            assert!(poll_once(&mut call).await);
        }
        Q.drain().await;
        assert_eq!(rows(&pool).await.len(), 1);
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (0, 0));
        assert!(s.last_success_at.is_some());
    }

    #[tokio::test]
    async fn record_counted_counts_an_unreachable_database() {
        queue!(C, Q, 64);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy(&format!("postgres://{}@127.0.0.1:1/x", "u"))
            .expect("lazy pool");
        record_counted(&pool, ev("ok", json!({})), &Q, LIMITS).await;
        Q.drain().await;
        let s = C.snapshot();
        assert_eq!((s.total, s.consecutive), (1, 1));
    }

    #[test]
    fn audit_safe_id_replaces_unsafe_characters_and_truncates() {
        assert_eq!(audit_safe_id("SV-1r1_rule.x:y"), "SV-1r1_rule.x:y");
        assert_eq!(audit_safe_id("a\u{0}b\"c\\d é"), "a?b?c?d??");
        assert_eq!(audit_safe_id(&"x".repeat(300)).len(), 64);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_detail_jsonb_rejects_is_retried_as_detail_dropped(pool: PgPool) {
        seed_user(&pool, "u1").await;
        // A NUL escape makes the jsonb cast fail on the first attempt.
        record_or_log(&pool, ev("ok", json!({ "ruleId": "a\u{0}b" }))).await;
        let got: Vec<(String, String)> =
            sqlx::query_as("SELECT outcome, detail::text FROM audit_events")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "ok");
        let d: Value = serde_json::from_str(&got[0].1).unwrap();
        assert_eq!(d, json!({ "detailDropped": true }));
    }

    #[test]
    fn bound_id_caps_and_sanitises() {
        assert_eq!(bound_id("abc-1.2_3:4"), "abc-1.2_3:4");
        assert_eq!(bound_id(&"a".repeat(100_000)).len(), MAX_ID_CHARS);
        assert_eq!(bound_id("a\u{0}b\"c"), "a?b?c");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn id_columns_are_bounded_on_insert(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let mut e = ev("denied", json!({}));
        let huge = "z".repeat(100_000);
        e.stig_id = Some(&huge);
        e.checklist_id = Some(&huge);
        record_or_log(&pool, e).await;
        let (a, b): (i32, i32) =
            sqlx::query_as("SELECT LENGTH(stig_id), LENGTH(checklist_id) FROM audit_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((a as usize, b as usize), (MAX_ID_CHARS, MAX_ID_CHARS));
    }

    #[tokio::test]
    async fn the_open_gauge_follows_non_restricted_reservations_only() {
        queue!(C, Q, 64);
        let g = Q.open_gauge();
        let mut held = vec![
            gated_submit(&Q, "a", false).await,
            gated_submit(&Q, "b", false).await,
            gated_submit(&Q, "c", true).await,
        ];
        assert_eq!((Q.pending(), g.load(Ordering::Relaxed)), (3, 2));
        // Finish the restricted one: the gauge is unchanged.
        let (open, call) = held.remove(2);
        let _ = open.send(());
        call.await;
        assert_eq!(Q.pending(), 2);
        assert_eq!(g.load(Ordering::Relaxed), 2);
        for (open, call) in held {
            let _ = open.send(());
            call.await;
        }
        Q.drain().await;
        assert_eq!(g.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn the_open_gauge_returns_to_zero_after_a_failed_write() {
        queue!(C, Q, 64);
        let (_open, gate) = tokio::sync::oneshot::channel::<()>();
        drop(_open);
        let mut call = Box::pin(submit(
            &Q,
            LONG,
            log_fields(),
            rsv("u1", false),
            gated_write(gate, Arc::new(AtomicBool::new(false)), false),
        ));
        let _ = poll_once(&mut call).await;
        call.await;
        Q.drain().await;
        assert_eq!(Q.open_gauge().load(Ordering::Relaxed), 0);
        assert_eq!(C.snapshot().total, 1);
    }

    #[tokio::test]
    async fn a_backlog_of_open_writes_refuses_admission_until_it_drains() {
        use crate::api::admission::{Admission, Refusal, AUDIT_BACKLOG_HIGH};
        queue!(C, Q, 64);
        let adm = Admission::with_backlog(Q.open_gauge());
        assert!(adm.try_admit("u0").is_ok());
        let mut held = Vec::new();
        for i in 0..AUDIT_BACKLOG_HIGH {
            held.push(gated_submit(&Q, &format!("u{i}"), false).await);
        }
        assert_eq!(adm.try_admit("fresh").unwrap_err(), Refusal::Backlog);
        for (open, call) in held {
            let _ = open.send(());
            call.await;
        }
        Q.drain().await;
        assert!(adm.try_admit("fresh").is_ok());
    }

    fn ctx() -> RequestCtx {
        RequestCtx {
            request_id: "req-1".into(),
            source_ip: Some("203.0.113.7".into()),
            role: "author".into(),
            audited: Default::default(),
            permit: None,
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_late_write_keeps_the_admission_permit_until_it_ends(pool: PgPool) {
        use sqlx::postgres::PgPoolOptions;
        queue!(C, Q, 64);
        seed_user(&pool, "u1").await;
        // A pool whose connections are all held, so the write cannot start.
        let small = PgPoolOptions::new()
            .max_connections(5)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(small.acquire().await.unwrap());
        }
        let adm = crate::api::admission::Admission::with_limits(
            crate::api::admission::MAX_IN_FLIGHT,
            crate::api::admission::MAX_USER_IN_FLIGHT,
            crate::api::admission::ADMIN_RESERVE,
        );
        let mut c = ctx();
        c.permit = Some(adm.try_admit("u1").unwrap());
        let mut e = ev("ok", json!({}));
        e.ctx = Some(&c);
        let limits = Limits {
            wait: std::time::Duration::ZERO,
            hard: HARD_WRITE_TIMEOUT,
        };
        record_counted(&small, e, &Q, limits).await;
        // The caller (and its ctx) is gone; the pending write still holds it.
        drop(c);
        assert_eq!(Q.pending(), 1);
        assert_eq!(adm.in_flight(), 1);
        drop(held);
        Q.drain().await;
        adm.idle().await;
        assert_eq!(adm.in_flight(), 0);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn request_context_columns_are_written_and_audited_is_set(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let c = ctx();
        let mut e = ev("ok", json!({}));
        e.ctx = Some(&c);
        record_or_log(&pool, e).await;
        assert!(c.audited.load(std::sync::atomic::Ordering::Relaxed));
        let got: (Option<String>, Option<String>, Option<String>) =
            sqlx::query_as("SELECT source_ip, request_id, user_role FROM audit_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            got,
            (
                Some("203.0.113.7".into()),
                Some("req-1".into()),
                Some("author".into())
            )
        );

        // No context: the columns stay NULL.
        record_or_log(&pool, ev("ok", json!({}))).await;
        let nulls: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE source_ip IS NULL AND request_id IS NULL AND user_role IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(nulls, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_detail_dropped_retry_keeps_the_context(pool: PgPool) {
        seed_user(&pool, "u1").await;
        let c = ctx();
        let mut e = ev("ok", json!({ "ruleId": "a\u{0}b" }));
        e.ctx = Some(&c);
        record_or_log(&pool, e).await;
        let got: (String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT detail::text, source_ip, request_id, user_role FROM audit_events",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&got.0).unwrap(),
            json!({ "detailDropped": true })
        );
        assert_eq!(
            (got.1.as_deref(), got.2.as_deref(), got.3.as_deref()),
            (Some("203.0.113.7"), Some("req-1"), Some("author"))
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn test_mode_is_rejected_unless_the_database_allows_it(pool: PgPool) {
        seed_both(&pool).await;
        let count = |pool: PgPool| async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM rule_audit")
                .fetch_one(&pool)
                .await
                .unwrap()
        };
        assert!(!test_maintenance_allowed(&pool).await.unwrap());
        for sql in [
            "UPDATE rule_audit SET field = 'x'",
            "TRUNCATE users CASCADE",
            "TRUNCATE rule_audit, audit_events",
        ] {
            let e = in_mode(&pool, "test", sql).await.unwrap_err();
            assert!(is_guard_error(&e), "{sql}: {e:#}");
            assert!(
                format!("{e:#}").contains("\"test\" is not enabled"),
                "{e:#}"
            );
        }
        assert_eq!(count(pool.clone()).await, 1);

        // A session-level SET cannot spoof the catalog flag.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('stig.audit_allow_test_mode', 'on', true)")
            .execute(&mut *tx)
            .await
            .unwrap();
        set_maintenance(&mut tx, "test").await.unwrap();
        let e = sqlx::query("UPDATE rule_audit SET field = 'x'")
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(
            e.as_database_error().and_then(|d| d.code()).as_deref(),
            Some("42501")
        );
        drop(tx);

        allow_audit_test_mode(&pool).await;
        assert!(test_maintenance_allowed(&pool).await.unwrap());
        in_mode(&pool, "test", "UPDATE rule_audit SET field = 'x'")
            .await
            .unwrap();
        assert!(is_guard_error(
            &in_mode(&pool, "test", "DELETE FROM rule_audit")
                .await
                .unwrap_err()
        ));
        in_mode(&pool, "test", "TRUNCATE rule_audit, audit_events")
            .await
            .unwrap();

        seed_both(&pool).await;
        disallow_audit_test_mode(&pool).await;
        assert!(!test_maintenance_allowed(&pool).await.unwrap());
        assert!(is_guard_error(
            &in_mode(&pool, "test", "UPDATE rule_audit SET field = 'y'")
                .await
                .unwrap_err()
        ));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn other_modes_do_not_need_the_test_flag(pool: PgPool) {
        seed_both(&pool).await;
        in_mode(&pool, "migration", "UPDATE rule_audit SET field = 'x'")
            .await
            .unwrap();
        in_mode(&pool, "retention", "DELETE FROM rule_audit")
            .await
            .unwrap();
        in_mode(&pool, "restore", "TRUNCATE rule_audit, audit_events")
            .await
            .unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn allow_test_maintenance_is_idempotent(pool: PgPool) {
        allow_test_maintenance(&pool).await.unwrap();
        allow_test_maintenance(&pool).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_catalog.pg_db_role_setting s \
             JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase \
             CROSS JOIN LATERAL unnest(s.setconfig) c \
             WHERE d.datname = current_database() AND s.setrole = 0 \
               AND c = 'stig.audit_allow_test_mode=on'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn test_maintenance_flag_startup_decision() {
        // (test_routes, flag_set)
        assert!(check_test_maintenance_flag(false, true).is_err());
        assert!(check_test_maintenance_flag(false, false).is_ok());
        assert!(check_test_maintenance_flag(true, true).is_ok());
        assert!(check_test_maintenance_flag(true, false).is_ok());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn startup_policy_sets_refuses_or_leaves_the_flag(pool: PgPool) {
        apply_test_maintenance_policy(&pool, false).await.unwrap();
        assert!(!test_maintenance_allowed(&pool).await.unwrap());
        apply_test_maintenance_policy(&pool, true).await.unwrap();
        assert!(test_maintenance_allowed(&pool).await.unwrap());
        assert!(apply_test_maintenance_policy(&pool, false).await.is_err());
        disallow_audit_test_mode(&pool).await;
        apply_test_maintenance_policy(&pool, false).await.unwrap();
        assert!(!test_maintenance_allowed(&pool).await.unwrap());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn flag_variants_do_not_enable_test_mode(pool: PgPool) {
        seed_both(&pool).await;
        for ddl in [
            "ALTER DATABASE %I SET stig.audit_allow_test_mode = 'true'",
            "ALTER DATABASE %I SET stig.audit_allow_test_mode = '1'",
            "ALTER ROLE CURRENT_USER IN DATABASE %I SET stig.audit_allow_test_mode = 'on'",
        ] {
            sqlx::query(&format!(
                "DO $$ BEGIN EXECUTE format($f${ddl}$f$, current_database()); END $$"
            ))
            .execute(&pool)
            .await
            .unwrap();
            assert!(!test_maintenance_allowed(&pool).await.unwrap(), "{ddl}");
            let e = in_mode(&pool, "test", "UPDATE rule_audit SET field = 'x'")
                .await
                .unwrap_err();
            assert!(is_guard_error(&e), "{ddl}: {e:#}");
            sqlx::query(
                "DO $$ BEGIN EXECUTE format('ALTER DATABASE %I RESET stig.audit_allow_test_mode', current_database()); \
                 EXECUTE format('ALTER ROLE CURRENT_USER IN DATABASE %I RESET stig.audit_allow_test_mode', current_database()); END $$",
            )
            .execute(&pool)
            .await
            .unwrap();
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_system_event_has_a_null_user_and_role_system(pool: PgPool) {
        queue!(C, Q, 64);
        let mk = || NewSystemEvent {
            action: "catalog.sync",
            outcome: "rejected",
            stig_id: Some("src-1"),
            detail: json!({"reasonCode": "download_too_large"}),
        };
        record_system_counted(&pool, mk(), &Q, LIMITS).await;
        record_system_counted(&pool, mk(), &Q, LIMITS).await;
        Q.drain().await;
        assert_eq!(C.snapshot().total, 0);
        let rows: Vec<(Option<String>, Option<String>, i32)> = sqlx::query_as(
            "SELECT user_id, user_role, repeat_count FROM audit_events WHERE action = 'catalog.sync'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        // Not collapsed: two rows, each with repeat_count 1.
        assert_eq!(rows.len(), 2, "{rows:?}");
        for (u, r, n) in rows {
            assert_eq!((u, r.as_deref(), n), (None, Some("system"), 1));
        }
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_null_user_without_role_system_violates_the_check(pool: PgPool) {
        for role in [None, Some("admin")] {
            let e = sqlx::query(
                "INSERT INTO audit_events (user_id, action, outcome, user_role) \
                 VALUES (NULL, 'catalog.sync', 'ok', $1)",
            )
            .bind(role)
            .execute(&pool)
            .await
            .unwrap_err();
            assert_eq!(
                e.as_database_error().and_then(|d| d.code()).as_deref(),
                Some("23514"),
                "{e}"
            );
        }
    }
}
