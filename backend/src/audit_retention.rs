//! Background prune of the `rule_audit` and `audit_events` tables.
//!
//! Both tables are append-only, so left unattended they grow unbounded. This
//! module trims rows older than `retain_days` and, optionally, archives them
//! on disk before deletion. Mirrors the scheduler pattern used elsewhere
//! (`sync`, dashboard snapshots, overdue digest) — a `tokio::spawn` loop in
//! `main.rs` drives it on a configurable interval.
//!
//! # Archive layout
//!
//! Each sweep writes immutable segments under `${data_dir}/audit_archive/`:
//!
//! - `rules-<UTC date>.<firstId>-<lastId>.jsonl` for `rule_audit`;
//! - `events-<UTC date>.<firstId>-<lastId>.jsonl` for `audit_events`;
//! - a sidecar `<segment>.manifest.json` per segment: an integrity envelope
//!   (see [`crate::integrity`]) whose signed payload records the stream, file
//!   name, row count, id range and the SHA-512 of the segment, plus the signer
//!   list. With `SIGNING_KEY_HEX` unset the sidecar carries the digest only,
//!   which detects corruption but not deliberate alteration.
//!
//! Segments are written to a uuid-named temp file (`create_new`), fsynced and
//! then published with a hard link, which never replaces an existing name
//! (the archive filesystem must support hard links, or retention fails
//! closed); the directory is then fsynced and a failed write leaves no
//! partial segment. A failed directory fsync aborts the sweep (nothing is
//! deleted) and unpublishes the file. That includes EINVAL/unsupported (some
//! CIFS/SMB and FUSE mounts): the sweep fails closed unless the operator opts
//! in with `AUDIT_ARCHIVE_ALLOW_UNSYNCED_DIR=true`, in which case the sweep
//! proceeds, logs once, and records the degraded durability in the scheduler
//! message and as the system audit event `audit_archive.durability_degraded`.
//! The sidecar is published BEFORE the segment, so a visible `.jsonl` always
//! has its complete sidecar and a concurrent scan can never see it as "sidecar
//! missing". A crash between the two leaves an orphan `*.manifest.json`, which
//! the scan ignores and the name pick steps over. At the start of each
//! archiving sweep, an orphan sidecar (segment absent, mtime at least 24 h
//! old) is renamed to `<sidecar>.orphan-<UTC ts>` and logged, never deleted:
//! it may be the only record of a lost segment.
//! Every file set aside (orphan sidecar or rejected segment) is also recorded
//! in the system audit event `audit_archive.file_set_aside`; a failed move is
//! counted there and in the scheduler message. These events are best effort
//! (shared audit write queue, may be shed under load); the scheduler message
//! and the `audit`-target log lines are the fallback record.
//! Retention deletes run through the owner-owned `audit_prune_*` functions
//! (migration 050): they declare the maintenance mode and the
//! `stig.audit_retention_protocol` marker (migration 047) themselves, refuse
//! rows younger than the database retention floor (`audit_policy`), and the
//! application role cannot DELETE audit rows directly. Older replicas that
//! still delete directly fail closed. [`check_floor`] makes a sweep fail
//! before archiving when `AUDIT_RETENTION_DAYS` is below the floor.
//! Sweeps are also serialized per database by an advisory lock
//! ([`crate::db_audit::lock_retention_sweep`]); a sweep that cannot get the
//! lock within five minutes fails and retries on the next tick. If the segment
//! write fails, the just-written sidecar is removed again.
//!
//! Archiving is idempotent by row id: ids already present in that date's
//! verified segments are skipped, so a retry after a failed delete never
//! duplicates a row.
//!
//! Only a segment that VERIFIES (sidecar present, digest, row count and id
//! range correct, and a verified signature when a key is configured) counts
//! as already archived. A planted, tampered or half-written segment is logged
//! (`audit` target) and ignored, so its rows are archived again; a duplicate
//! is harmless, a lost row is not.
//!
//! Files from earlier versions (`<date>.jsonl`, `events-<date>.jsonl`,
//! append-mode) are legacy: never rewritten, never signed, no manifest, and
//! never trusted to skip a row.
//!
//! Ordering: rows are archived (fsynced) BEFORE the delete transaction runs,
//! so a row is never deleted unarchived. If the archive write fails the sweep
//! stops with an error and nothing is deleted; if the delete fails after a
//! successful archive, the retry skips the already-archived ids.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::signing::SigningState;
use crate::integrity::{self, SignatureStatus, SignerId};

/// One `rule_audit` row, shaped for JSONL archival. Matches the table
/// columns 1:1 — we deliberately do not denormalize user/asset names
/// here because the live view (`/api/activity`, rule history) already
/// joins those in, and the archive should be a faithful raw record.
#[derive(Debug, Serialize, sqlx::FromRow)]
struct AuditRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    user_id: String,
    checklist_id: String,
    rule_id: String,
    field: String,
    from_value: Option<String>,
    to_value: Option<String>,
}

// ── Archive segments ────────────────────────────────────────────────────────

/// `AUDIT_RETENTION_DAYS` (default 365), shared by the scheduler and the owner step.
pub fn retain_days_from_env() -> i64 {
    std::env::var("AUDIT_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(365)
}

/// Fail when `retain_days` is below the database retention floor, before
/// anything is archived: the prune function would refuse the rows anyway.
async fn check_floor(pool: &PgPool, retain_days: i64) -> Result<()> {
    let floor: i32 = sqlx::query_scalar("SELECT min_retain_days FROM audit_policy")
        .fetch_one(pool)
        .await
        .context("read the audit retention floor")?;
    if retain_days < i64::from(floor) {
        anyhow::bail!(
            "AUDIT_RETENTION_DAYS ({retain_days}) is below the database retention floor \
             ({floor}); run `migrate` with AUDIT_RETENTION_DAYS={retain_days} as the owner \
             to lower it"
        );
    }
    Ok(())
}

/// Value of `stig.audit_retention_protocol` the DB guard (migration 047)
/// requires for a retention DELETE. Older versions never set it. Production
/// code no longer declares it: the prune functions do.
#[cfg(test)]
pub(crate) const RETENTION_PROTOCOL: &str = "2";

/// Declare retention mode plus the protocol marker for this transaction.
#[cfg(test)]
pub(crate) async fn declare_retention_delete(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<()> {
    crate::db_audit::set_maintenance(tx, "retention").await?;
    sqlx::query("SELECT set_config('stig.audit_retention_protocol', $1, true)")
        .bind(RETENTION_PROTOCOL)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

const STREAM_RULES: &str = "rules";
const STREAM_EVENTS: &str = "events";

/// One serialized row waiting to be archived.
struct ArchiveLine {
    id: i64,
    occurred_at: DateTime<Utc>,
    line: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Digest {
    algorithm: String,
    value: String,
}

/// Signed payload of a segment sidecar. Field order is the serialized order.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SegmentManifest {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    stream: String,
    file: String,
    rows: u64,
    first_id: i64,
    last_id: i64,
    digest: Digest,
    signers: Vec<SignerId>,
}

/// `(first, last)` from the part of a segment name after `<stream>-<date>.`:
/// `<first>-<last>` or, for a collision-free rewrite, `<first>-<last>.r<n>`.
fn parse_range(rest: &str) -> Option<(i64, i64)> {
    let (range, rev) = match rest.split_once('.') {
        Some((r, v)) => (r, Some(v)),
        None => (rest, None),
    };
    if let Some(v) = rev {
        let n = v.strip_prefix('r')?;
        if n.is_empty() || !n.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    let (a, b) = range.split_once('-')?;
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    if !digits(a) || !digits(b) {
        return None;
    }
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// `(first, last)` if `name` is a segment of `stream` on `date`.
fn segment_range(name: &str, stream: &str, date: &str) -> Option<(i64, i64)> {
    parse_range(
        name.strip_prefix(&format!("{stream}-{date}."))?
            .strip_suffix(".jsonl")?,
    )
}

#[derive(Deserialize)]
struct IdOnly {
    id: i64,
}

/// `(id, SHA-512 of the exact line)` for every line of a segment.
fn lines_in(bytes: &[u8]) -> Result<Vec<(i64, String)>> {
    bytes
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_slice::<IdOnly>(l)
                .map(|r| (r.id, integrity::sha512_hex(l)))
                .map_err(|_| anyhow::anyhow!("archive segment has a line without an id"))
        })
        .collect()
}

/// How a directory fsync that the filesystem does not support is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum DirSyncPolicy {
    /// An unsupported directory fsync fails the archive step (the default).
    #[default]
    FailClosed,
    /// Operator opt-in: proceed without a directory fsync and record it.
    TolerateUnsupported,
}

/// Env switch that selects [`DirSyncPolicy::TolerateUnsupported`].
const ALLOW_UNSYNCED_DIR_ENV: &str = "AUDIT_ARCHIVE_ALLOW_UNSYNCED_DIR";

impl DirSyncPolicy {
    /// Only `true` / `1` (trimmed, case-insensitive) opt in; anything else
    /// fails closed.
    fn from_raw(raw: Option<&str>) -> Self {
        if crate::config::parse_flag(raw) {
            Self::TolerateUnsupported
        } else {
            Self::FailClosed
        }
    }

    fn from_env() -> Self {
        let policy = Self::from_raw(std::env::var(ALLOW_UNSYNCED_DIR_ENV).ok().as_deref());
        if policy == Self::TolerateUnsupported {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                tracing::warn!(target: "audit", "{ALLOW_UNSYNCED_DIR_ENV} is set: audit archive directory entries may be non-durable on filesystems without directory fsync");
            });
        }
        policy
    }
}

/// One archive file set aside (or that could not be).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SetAside {
    from: String,
    to: Option<String>,
    /// `"orphan"`, `"rejected"` or `"tidy_task_failed"` (the tidy task itself
    /// died; `from` is then a placeholder, and it counts as a failed move).
    reason: &'static str,
    error: Option<String>,
}

/// Things a sweep did to the archive that must be reported afterwards.
#[derive(Debug, Default)]
struct SweepNotes {
    set_aside: Vec<SetAside>,
    unsynced_publishes: u32,
}

impl SweepNotes {
    fn moved(&self) -> usize {
        self.set_aside.iter().filter(|s| s.error.is_none()).count()
    }

    fn failed_moves(&self) -> usize {
        self.set_aside.iter().filter(|s| s.error.is_some()).count()
    }

    fn is_empty(&self) -> bool {
        self.set_aside.is_empty() && self.unsynced_publishes == 0
    }

    fn merge(&mut self, other: SweepNotes) {
        self.set_aside.extend(other.set_aside);
        self.unsynced_publishes += other.unsynced_publishes;
    }
}

/// Archive-writing state that is not the seen-cache.
#[derive(Debug, Default)]
struct ArchiveIo {
    policy: DirSyncPolicy,
    notes: SweepNotes,
}

/// Per-sweep state. `seen` and `io` are separate fields so both can be
/// borrowed at once.
#[derive(Debug, Default)]
struct SweepCtx {
    seen: SeenCache,
    io: ArchiveIo,
}

impl SweepCtx {
    fn new(policy: DirSyncPolicy) -> Self {
        Self {
            seen: SeenCache::new(),
            io: ArchiveIo {
                policy,
                notes: SweepNotes::default(),
            },
        }
    }
}

/// Move a rejected segment (and its sidecar) aside as
/// `<name>.rejected-<UTC timestamp>` so it is kept as evidence and never
/// counted again.
fn preserve_rejected(dir: &Path, name: &str, notes: &mut SweepNotes) {
    for file in [name.to_string(), format!("{name}.manifest.json")] {
        notes.set_aside.extend(move_aside(dir, &file, "rejected"));
    }
}

/// Directories whose move-aside is forced to fail (test hook; keyed on the
/// unique temp dir so parallel tests stay isolated).
#[cfg(test)]
static FAIL_MOVE_ASIDE: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

/// Longest error text kept in a [`SetAside`].
const MAX_SET_ASIDE_ERROR_CHARS: usize = 200;

/// Rename `dir/file` to `<file>.<label>-<UTC ts>` (uuid suffix if that exists).
/// Returns what happened; a missing file is not an error (`None`).
fn move_aside(dir: &Path, file: &str, label: &'static str) -> Option<SetAside> {
    let ts = Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
    let from = dir.join(file);
    if !from.exists() {
        return None;
    }
    // Hard link then remove the source: never replaces an existing target.
    let mut to = dir.join(format!("{file}.{label}-{ts}"));
    #[cfg(test)]
    let forced = FAIL_MOVE_ASIDE
        .lock()
        .map(|set| set.iter().any(|p| p == dir))
        .unwrap_or(false);
    #[cfg(not(test))]
    let forced = false;
    let mut result = if forced {
        Err(std::io::Error::other("injected move failure"))
    } else {
        std::fs::hard_link(&from, &to)
    };
    for _ in 0..8 {
        if !matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists) {
            break;
        }
        to = dir.join(format!(
            "{file}.{label}-{ts}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        result = std::fs::hard_link(&from, &to);
    }
    match result.and_then(|()| std::fs::remove_file(&from)) {
        Ok(()) => {
            tracing::warn!(target: "audit", from = ?file, to = ?to.file_name(), "audit archive file preserved as {label}");
            Some(SetAside {
                from: file.to_string(),
                to: to.file_name().map(|n| n.to_string_lossy().into_owned()),
                reason: label,
                error: None,
            })
        }
        Err(e) => {
            tracing::error!(target: "audit", file = ?file, "could not preserve {label} audit archive file: {e:#}");
            // Store the bare io::Error text only: no path or anyhow context,
            // because it lands in the audit event detail.
            Some(SetAside {
                from: file.to_string(),
                to: None,
                reason: label,
                error: Some(bounded_error(&e)),
            })
        }
    }
}

/// The bare error text, cut to [`MAX_SET_ASIDE_ERROR_CHARS`] characters
/// (never mid-character). Callers pass the bare `io::Error` (no path, no
/// anyhow context) because the text lands in the audit event detail.
fn bounded_error(e: &dyn std::fmt::Display) -> String {
    e.to_string()
        .chars()
        .take(MAX_SET_ASIDE_ERROR_CHARS)
        .collect()
}

/// Minimum sidecar age before it is treated as an orphan: protects a sweep
/// that lost its lock and is still between sidecar and segment.
const ORPHAN_SIDECAR_MIN_AGE: Duration = Duration::from_secs(24 * 3600);

/// Rename sidecars whose segment is definitely absent and that are at least
/// `min_age` old to `<sidecar>.orphan-<ts>`. Returns every move attempted.
fn set_aside_orphan_sidecars(dir: &Path, min_age: Duration) -> Vec<SetAside> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let Some(file) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(seg) = file.strip_suffix(".manifest.json") else {
            continue;
        };
        if !seg.ends_with(".jsonl") || segment_range_any(seg).is_none() {
            continue;
        }
        let stream_ok = seg.starts_with("rules-") || seg.starts_with("events-");
        if !stream_ok {
            continue;
        }
        match std::fs::symlink_metadata(dir.join(seg)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => continue,
        }
        let old_enough = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= min_age);
        if old_enough {
            out.extend(move_aside(dir, &file, "orphan"));
        }
    }
    out
}

/// Tidy the archive directory (orphan sidecars) under the sweep lock.
/// Failures are logged and never fail the sweep; every move (including a
/// failed one) is added to `notes`.
async fn tidy_archive(data_dir: &Path, notes: &mut SweepNotes) {
    let dir = data_dir.join("audit_archive");
    let res = tokio::task::spawn_blocking(move || {
        if !dir.is_dir() {
            return Vec::new();
        }
        set_aside_orphan_sidecars(&dir, ORPHAN_SIDECAR_MIN_AGE)
    })
    .await;
    match res {
        Ok(moves) => notes.set_aside.extend(moves),
        Err(e) => {
            tracing::error!(target: "audit", "audit archive tidy failed: {e:#}");
            notes.set_aside.push(SetAside {
                from: "(archive tidy task)".to_string(),
                to: None,
                reason: "tidy_task_failed",
                error: Some(bounded_error(&e)),
            });
        }
    }
}

/// What the verified segments of `stream` on `date` hold: id -> SHA-512s of
/// the exact lines. A segment counts only if it VERIFIES (sidecar present;
/// digest, row count and id range correct; a verified signature when a key is
/// configured).
///
/// - A DEFINITE failure (bad signature, digest, count or range mismatch, a
///   missing or unparseable sidecar) is logged, the segment and sidecar are
///   preserved as `*.rejected-<time>`, and it is not counted.
/// - Anything inexact (an I/O error, or `Unsigned` / `UnknownKey` while a key
///   is configured, as after a key change) is logged, not counted, and left
///   untouched. New segments are written under non-colliding names.
///
/// The caller skips a row only when its id maps to the identical line, so a
/// planted segment with a consistent digest cannot hide a real row, with or
/// without a signing key. Legacy append-mode files are never read.
fn archived_lines(
    dir: &Path,
    stream: &str,
    date: &str,
    key: Option<&SigningState>,
    notes: &mut SweepNotes,
) -> Result<HashMap<i64, HashSet<String>>> {
    let mut seen: HashMap<i64, HashSet<String>> = HashMap::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if segment_range(&name, stream, date).is_none() {
            continue;
        }
        let v = match verify_segment(dir, &name, key) {
            Ok(v) => v,
            Err(SegmentError::Definite(e)) => {
                tracing::warn!(
                    target: "audit",
                    segment = ?name,
                    "audit archive segment failed verification, its rows will be archived again: {e:#}"
                );
                preserve_rejected(dir, &name, notes);
                continue;
            }
            Err(SegmentError::Transient(e)) => {
                tracing::warn!(target: "audit", segment = ?name, "audit archive segment could not be read, left in place and not counted: {e:#}");
                continue;
            }
        };
        if key.is_some() && v.status != SignatureStatus::Verified {
            tracing::warn!(
                target: "audit",
                segment = ?name,
                "audit archive segment is {} under the configured key, left in place and not counted",
                v.status.as_str()
            );
            continue;
        }
        match lines_in(&v.body) {
            Ok(lines) => {
                for (id, digest) in lines {
                    let set = seen.entry(id).or_default();
                    set.insert(digest);
                    if key.is_none() && set.len() > 1 {
                        tracing::warn!(target: "audit", segment = ?name, id, "audit archive holds different lines for one id across verified segments");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "audit", segment = ?name, "audit archive segment unreadable, not counted: {e:#}")
            }
        }
    }
    Ok(seen)
}

/// Whether a failed `fsync` of the archive directory must abort the sweep.
///
/// EINVAL and "unsupported" from `fsync(dirfd)` are a static property of the
/// filesystem (some CIFS/SMB and FUSE mounts). By default they are fatal like
/// every other error (the archive would otherwise be silently non-durable);
/// only with [`DirSyncPolicy::TolerateUnsupported`] are they tolerated. Every
/// other error (EIO, ENOSPC, EDQUOT, EACCES, ...) is always a real durability
/// failure.
fn dir_sync_is_fatal(e: &std::io::Error, policy: DirSyncPolicy) -> bool {
    policy == DirSyncPolicy::FailClosed
        || !matches!(
            e.kind(),
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
        )
}

/// Result of a directory sync that did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirSynced {
    Durable,
    /// The filesystem does not support it and the policy tolerated that.
    Unsupported,
}

/// The error for an unsupported directory fsync under [`DirSyncPolicy::FailClosed`].
fn fail_closed_dir_sync_error(e: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        e.kind(),
        format!("directory fsync is not supported on this filesystem ({e}); retention fails closed. Set {ALLOW_UNSYNCED_DIR_ENV}=true to accept non-durable archive directory entries"),
    )
}

/// Directories whose sync is forced to fail with the given kind (test hook;
/// keyed on the unique temp dir so parallel tests stay isolated).
#[cfg(test)]
static FAIL_DIR_SYNC: std::sync::Mutex<Vec<(std::path::PathBuf, std::io::ErrorKind)>> =
    std::sync::Mutex::new(Vec::new());

/// The injected failure for `dir`, if armed. Shared by both `sync_dir` variants.
#[cfg(test)]
fn injected_dir_sync_failure(dir: &Path) -> Option<std::io::Error> {
    let set = FAIL_DIR_SYNC.lock().ok()?;
    let (_, kind) = set.iter().find(|(p, _)| p == dir)?;
    Some(std::io::Error::new(
        *kind,
        "injected directory sync failure",
    ))
}

#[cfg(unix)]
/// Report a tolerated (unsupported) directory fsync once per process, loudly:
/// archive durability is degraded on this filesystem.
fn note_dir_sync_unsupported(dir: &Path, e: &std::io::Error) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tracing::error!(target: "audit", dir = ?dir, "directory fsync is not supported on this filesystem: audit archive durability is degraded (logged once): {e}");
    });
}

/// Apply `policy` to a failed directory fsync.
#[cfg(unix)]
fn classify_dir_sync(
    dir: &Path,
    result: std::io::Result<()>,
    policy: DirSyncPolicy,
) -> std::io::Result<DirSynced> {
    match result {
        Ok(()) => Ok(DirSynced::Durable),
        Err(e) if !dir_sync_is_fatal(&e, policy) => {
            note_dir_sync_unsupported(dir, &e);
            Ok(DirSynced::Unsupported)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
            ) =>
        {
            Err(fail_closed_dir_sync_error(&e))
        }
        Err(e) => Err(e),
    }
}

/// fsync the directory so a rename in it is durable. An unsupported fsync is
/// an error unless `policy` tolerates it (then it is reported once and
/// returned as [`DirSynced::Unsupported`]).
#[cfg(unix)]
fn sync_dir(dir: &Path, policy: DirSyncPolicy) -> std::io::Result<DirSynced> {
    let result = (|| {
        #[cfg(test)]
        if let Some(e) = injected_dir_sync_failure(dir) {
            return Err(e);
        }
        std::fs::File::open(dir)?.sync_all()
    })();
    classify_dir_sync(dir, result, policy)
}

/// Best effort off unix: opening a directory as a file fails on Windows. Only
/// an injected (test) failure is subject to the policy.
#[cfg(not(unix))]
fn sync_dir(dir: &Path, policy: DirSyncPolicy) -> std::io::Result<DirSynced> {
    #[cfg(test)]
    if let Some(e) = injected_dir_sync_failure(dir) {
        return if !dir_sync_is_fatal(&e, policy) {
            Ok(DirSynced::Unsupported)
        } else if matches!(
            e.kind(),
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
        ) {
            Err(fail_closed_dir_sync_error(&e))
        } else {
            Err(e)
        };
    }
    let _ = policy;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(DirSynced::Durable)
}

/// Outcome of [`publish_new`].
#[derive(Debug, PartialEq, Eq)]
enum Publish {
    Created,
    Taken,
}

/// Test hook stages of [`write_segment_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStage {
    /// Candidate name chosen, nothing published yet.
    NamePicked,
    /// Sidecar durable, segment not yet published.
    SidecarPublished,
}

/// Upper bound on `.r<n>` candidates tried per segment.
const MAX_NAME_ATTEMPTS: u32 = 1000;

/// Write a uuid-named temp file (`create_new`), fsync it, then hard-link it to
/// `name`: a hard link never replaces an existing file, so a taken name is
/// reported as `Taken` and left untouched. A directory sync failure is an
/// error (the caller aborts before any row is deleted); the just-published
/// name is removed again so no unsynced file stays visible.
fn publish_new(dir: &Path, name: &str, bytes: &[u8], io: &mut ArchiveIo) -> Result<Publish> {
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<Publish> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        match std::fs::hard_link(&tmp, dir.join(name)) {
            Ok(()) => Ok(Publish::Created),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(Publish::Taken),
            Err(e) => Err(anyhow::Error::new(e)
                .context("hard link failed; the audit archive filesystem must support hard links")),
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    let published = result.with_context(|| format!("write {name}"))?;
    if published == Publish::Created {
        match sync_dir(dir, io.policy) {
            Ok(DirSynced::Durable) => {}
            // May over-count when the sidecar was tolerated and the segment
            // publish then fails: errs toward reporting.
            Ok(DirSynced::Unsupported) => io.notes.unsynced_publishes += 1,
            Err(e) => {
                // The hard link just created this name, so it is ours to remove.
                let _ = std::fs::remove_file(dir.join(name));
                return Err(e).with_context(|| format!("sync directory after publishing {name}"));
            }
        }
    }
    Ok(published)
}

fn write_segment(
    dir: &Path,
    stream: &str,
    date: &str,
    group: &[&ArchiveLine],
    key: Option<&SigningState>,
    io: &mut ArchiveIo,
) -> Result<()> {
    write_segment_with(dir, stream, date, group, key, &|_, _| Ok(()), io)
}

/// Sidecar first, then segment. `hook` is a test hook called at each
/// [`WriteStage`] with the candidate segment name.
fn write_segment_with(
    dir: &Path,
    stream: &str,
    date: &str,
    group: &[&ArchiveLine],
    key: Option<&SigningState>,
    hook: &dyn Fn(WriteStage, &str) -> Result<()>,
    io: &mut ArchiveIo,
) -> Result<()> {
    let (Some(first), Some(last)) = (group.first(), group.last()) else {
        return Ok(());
    };
    let mut body = Vec::new();
    for l in group {
        body.extend_from_slice(l.line.as_bytes());
        body.push(b'\n');
    }
    // Never replace an existing file: claim the sidecar name (a hard link
    // fails if it exists), trying `.r<n>` until one is ours.
    for n in 0..MAX_NAME_ATTEMPTS {
        let name = if n == 0 {
            format!("{stream}-{date}.{}-{}.jsonl", first.id, last.id)
        } else {
            format!("{stream}-{date}.{}-{}.r{n}.jsonl", first.id, last.id)
        };
        let sidecar = format!("{name}.manifest.json");
        if dir.join(&name).exists() || dir.join(&sidecar).exists() {
            continue;
        }
        hook(WriteStage::NamePicked, &name)?;
        // `file` is in the signed payload, so the manifest is built per name.
        let manifest = SegmentManifest {
            kind: integrity::ARCHIVE_TYPE.into(),
            version: 1,
            stream: stream.into(),
            file: name.clone(),
            rows: group.len() as u64,
            first_id: first.id,
            last_id: last.id,
            digest: Digest {
                algorithm: "sha-512".into(),
                value: integrity::sha512_hex(&body),
            },
            signers: integrity::signers_for(key),
        };
        let payload = serde_json::to_vec(&manifest)?;
        let envelope = integrity::seal(
            integrity::ARCHIVE_DOMAIN,
            integrity::ARCHIVE_TYPE,
            &payload,
            key,
        );
        if publish_new(dir, &sidecar, &serde_json::to_vec_pretty(&envelope)?, io)? == Publish::Taken
        {
            continue;
        }
        // Once the sidecar name is ours, no cooperating sweep can create this
        // segment; a file there is foreign, so fail rather than retry. Any
        // failure removes the sidecar we just published.
        let published =
            hook(WriteStage::SidecarPublished, &name).and_then(|()| {
                match publish_new(dir, &name, &body, io)? {
                    Publish::Created => Ok(()),
                    Publish::Taken => Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "segment name already taken",
                    ))
                    .with_context(|| format!("segment {name} already exists")),
                }
            });
        if published.is_err() {
            let _ = std::fs::remove_file(dir.join(&sidecar));
        }
        return published;
    }
    anyhow::bail!("no free archive segment name after {MAX_NAME_ATTEMPTS} attempts")
}

/// Verified archived lines (id -> line digest) per UTC date, for one sweep.
type SeenCache = HashMap<String, HashMap<i64, HashSet<String>>>;

fn archive_blocking(
    data_dir: &Path,
    stream: &str,
    rows: Vec<ArchiveLine>,
    key: Option<&SigningState>,
    ctx: &mut SweepCtx,
) -> Result<()> {
    let dir = data_dir.join("audit_archive");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create archive dir {}", dir.display()))?;
    // Group by UTC date; `occurred_at` can be out of order versus id.
    let mut by_date: BTreeMap<String, Vec<&ArchiveLine>> = BTreeMap::new();
    for row in &rows {
        by_date
            .entry(row.occurred_at.format("%Y-%m-%d").to_string())
            .or_default()
            .push(row);
    }
    for (date, mut group) in by_date {
        if !ctx.seen.contains_key(&date) {
            let lines = archived_lines(&dir, stream, &date, key, &mut ctx.io.notes)?;
            ctx.seen.insert(date.clone(), lines);
        }
        let seen = ctx.seen.entry(date.clone()).or_default();
        // Skip a row only when a verified segment holds this exact line.
        group.retain(|l| {
            !seen
                .get(&l.id)
                .is_some_and(|h| h.contains(&integrity::sha512_hex(l.line.as_bytes())))
        });
        group.sort_by_key(|l| l.id);
        group.dedup_by_key(|l| l.id);
        write_segment(&dir, stream, &date, &group, key, &mut ctx.io)?;
        for l in &group {
            seen.entry(l.id)
                .or_default()
                .insert(integrity::sha512_hex(l.line.as_bytes()));
        }
    }
    Ok(())
}

async fn archive_rows(
    data_dir: &Path,
    stream: &'static str,
    rows: Vec<ArchiveLine>,
    key: Option<&SigningState>,
    ctx: &mut SweepCtx,
) -> Result<()> {
    let data_dir = data_dir.to_path_buf();
    let key = key.cloned();
    let mut local = std::mem::take(ctx);
    let (res, local) = tokio::task::spawn_blocking(move || {
        let r = archive_blocking(&data_dir, stream, rows, key.as_ref(), &mut local);
        (r, local)
    })
    .await
    .context("archive task")?;
    *ctx = local;
    res
}

/// A segment that passed [`verify_segment`]: the bytes that were verified, so
/// callers read the file only once.
pub struct VerifiedSegment {
    pub status: SignatureStatus,
    pub body: Vec<u8>,
}

/// Verify one archive segment against its sidecar: the envelope (signature,
/// when present), then the file name, row count, id range and SHA-512. The
/// returned bytes are the ones the digest was computed over. Legacy files have
/// no sidecar and cannot be verified.
pub fn verify_segment(
    dir: &Path,
    segment: &str,
    key: Option<&SigningState>,
) -> Result<VerifiedSegment, SegmentError> {
    let body = std::fs::read(dir.join(segment))
        .map_err(|e| SegmentError::Transient(anyhow::Error::from(e).context("read segment")))?;
    let sidecar = match std::fs::read(dir.join(format!("{segment}.manifest.json"))) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SegmentError::Definite(anyhow::anyhow!(
                "sidecar manifest is missing"
            )))
        }
        Err(e) => {
            return Err(SegmentError::Transient(
                anyhow::Error::from(e).context("read sidecar"),
            ))
        }
    };
    check_segment(segment, &body, &sidecar, key).map_err(SegmentError::Definite)
}

fn check_segment(
    segment: &str,
    body: &[u8],
    sidecar: &[u8],
    key: Option<&SigningState>,
) -> Result<VerifiedSegment> {
    let v = integrity::verify_envelope(
        integrity::ARCHIVE_DOMAIN,
        integrity::ARCHIVE_TYPE,
        sidecar,
        None,
        key,
    )?;
    let m: SegmentManifest = serde_json::from_slice(&v.payload)?;
    anyhow::ensure!(m.file == segment, "manifest is for another file");
    anyhow::ensure!(
        m.digest.algorithm == "sha-512",
        "unsupported digest algorithm"
    );
    anyhow::ensure!(
        m.digest.value == integrity::sha512_hex(body),
        "segment digest mismatch"
    );
    let ids: Vec<i64> = lines_in(body)?.into_iter().map(|(i, _)| i).collect();
    anyhow::ensure!(ids.len() as u64 == m.rows, "row count mismatch");
    let range = segment_range_any(segment).context("segment file name is not a segment name")?;
    anyhow::ensure!(
        ids.iter().all(|&i| i >= range.0 && i <= range.1) && (m.first_id, m.last_id) == range,
        "ids outside the range in the segment name"
    );
    anyhow::ensure!(
        ids.iter().min() == Some(&m.first_id) && ids.iter().max() == Some(&m.last_id),
        "id range mismatch"
    );
    Ok(VerifiedSegment {
        status: v.status,
        body: body.to_vec(),
    })
}

/// Why a segment did not verify. Only a `Definite` failure justifies
/// quarantining the files; an I/O error proves nothing about them.
#[derive(Debug)]
pub enum SegmentError {
    Definite(anyhow::Error),
    Transient(anyhow::Error),
}

impl std::fmt::Display for SegmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Definite(e) | Self::Transient(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for SegmentError {}

/// Range from a segment file name of any stream and date.
fn segment_range_any(name: &str) -> Option<(i64, i64)> {
    let (_, rest) = name.strip_suffix(".jsonl")?.split_once('.')?;
    parse_range(rest)
}

// ── rule_audit ──────────────────────────────────────────────────────────────

/// Prune `rule_audit` rows older than `retain_days`. When `archive` is
/// true, each pruned row is first written to an immutable, manifest-backed
/// segment (see the module docs). Returns the number of rows deleted.
///
/// The fetch + delete pair is not strictly transactional — between
/// SELECT and DELETE a concurrent writer could insert a new row that
/// also happens to fall before the cutoff. That's fine: such a row
/// will be archived on the next sweep. We intentionally pin the
/// DELETE to the exact id set we just read so we never delete a row
/// we didn't archive.
///
/// Sweeps are serialized per database by an advisory lock held for the whole
/// call (a second sweep waits), so one sweep never scans a segment another is
/// writing. Segments are written sidecar-first, so even without the lock a
/// live segment is never seen as missing its sidecar.
pub async fn run_prune(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
) -> Result<usize> {
    run_prune_noted(
        pool,
        data_dir,
        retain_days,
        archive,
        signing,
        crate::db_audit::RETENTION_LOCK_WAIT,
        DirSyncPolicy::from_env(),
    )
    .await
    .0
}

/// Roll back the lock transaction (releasing the lock); a failure is logged.
async fn release_lock(lock: sqlx::Transaction<'static, sqlx::Postgres>) {
    if let Err(e) = lock.rollback().await {
        tracing::warn!(target: "audit", "retention sweep lock rollback failed: {e:#}");
    }
}

/// [`run_prune`] with an explicit policy, also returning what the sweep set
/// aside; the notes are recorded as audit events before returning.
async fn run_prune_noted(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
    lock_wait: std::time::Duration,
    policy: DirSyncPolicy,
) -> (Result<usize>, SweepNotes) {
    let mut lock = match crate::db_audit::lock_retention_sweep(pool, lock_wait).await {
        Ok(l) => l,
        Err(e) => {
            return (
                Err(e).context("take retention sweep lock"),
                SweepNotes::default(),
            )
        }
    };
    let mut ctx = SweepCtx::new(policy);
    let result = prune_rules_locked(
        pool,
        data_dir,
        retain_days,
        archive,
        signing,
        &mut lock,
        &mut ctx,
    )
    .await;
    release_lock(lock).await;
    let notes = ctx.io.notes;
    record_sweep_notes(pool, STREAM_RULES, &notes, result.is_ok()).await;
    (result, notes)
}

async fn prune_rules_locked(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
    lock: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &mut SweepCtx,
) -> Result<usize> {
    check_floor(pool, retain_days).await?;
    if archive {
        tidy_archive(data_dir, &mut ctx.io.notes).await;
    }
    // Build the cutoff in Rust rather than embedding `retain_days` in
    // SQL — Postgres rejects negative INTERVAL composed via string
    // concat in some setups, and this is easier to reason about.
    let rows: Vec<AuditRow> = sqlx::query_as::<_, AuditRow>(
        r#"
        SELECT id, occurred_at, user_id, checklist_id, rule_id, field, from_value, to_value
        FROM rule_audit
        WHERE occurred_at < NOW() - ($1 || ' days')::INTERVAL
        ORDER BY id ASC
        "#,
    )
    .bind(retain_days.to_string())
    .fetch_all(pool)
    .await
    .context("select expired rule_audit rows")?;

    if rows.is_empty() {
        return Ok(0);
    }

    // Archive first: an error here returns before any delete is attempted.
    if archive {
        let lines = rows
            .iter()
            .map(|r| {
                Ok(ArchiveLine {
                    id: r.id,
                    occurred_at: r.occurred_at,
                    line: serde_json::to_string(r).context("serialize audit row")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        crate::db_audit::retention_lock_alive(lock).await?;
        archive_rows(data_dir, STREAM_RULES, lines, signing, ctx)
            .await
            .context("write audit archive segment")?;
    }

    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    crate::db_audit::retention_lock_alive(lock).await?;
    let deleted: i64 = sqlx::query_scalar("SELECT audit_prune_rule_audit($1::bigint[])")
        .bind(&ids)
        .fetch_one(pool)
        .await
        .context("delete pruned rule_audit rows")?;

    Ok(deleted as usize)
}

/// One `audit_events` row, shaped for JSONL archival (raw columns).
#[derive(Debug, Serialize, sqlx::FromRow)]
struct EventRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    user_id: Option<String>,
    action: String,
    outcome: String,
    asset_id: Option<String>,
    checklist_id: Option<String>,
    stig_id: Option<String>,
    source_ip: Option<String>,
    request_id: Option<String>,
    user_role: Option<String>,
    repeat_count: i32,
    last_occurred_at: Option<DateTime<Utc>>,
    /// `detail::text`, re-parsed into JSON when archived.
    detail: String,
}

/// Rows per select/archive/delete round of [`run_prune_events`].
const EVENT_PRUNE_BATCH: i64 = 5_000;

/// Same as [`run_prune`] for `audit_events` (same cutoff, same id-pinned
/// delete), but in bounded batches: any user with write access can create
/// rows, so a sweep must not load them all at once. Each batch is archived
/// before it is deleted. Archived to
/// `${data_dir}/audit_archive/events-<date>.<firstId>-<lastId>.jsonl`.
pub async fn run_prune_events(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
) -> Result<usize> {
    run_prune_events_noted(
        pool,
        data_dir,
        retain_days,
        archive,
        signing,
        DirSyncPolicy::from_env(),
    )
    .await
    .0
}

/// [`run_prune_events`] with an explicit policy, also returning the notes.
async fn run_prune_events_noted(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
    policy: DirSyncPolicy,
) -> (Result<usize>, SweepNotes) {
    run_prune_events_with(
        pool,
        data_dir,
        retain_days,
        archive,
        EVENT_PRUNE_BATCH,
        signing,
        &|_| Box::pin(async {}),
        policy,
    )
    .await
}

/// Test hook run after each committed batch (with the batch number).
type AfterBatch<'a> =
    &'a (dyn Fn(usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Sync);

#[cfg(test)]
async fn run_prune_events_batched(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    batch: i64,
    signing: Option<&SigningState>,
) -> Result<usize> {
    run_prune_events_with(
        pool,
        data_dir,
        retain_days,
        archive,
        batch,
        signing,
        &|_| Box::pin(async {}),
        DirSyncPolicy::FailClosed,
    )
    .await
    .0
}

#[allow(clippy::too_many_arguments)]
async fn run_prune_events_with(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    batch: i64,
    signing: Option<&SigningState>,
    after_batch: AfterBatch<'_>,
    policy: DirSyncPolicy,
) -> (Result<usize>, SweepNotes) {
    let mut lock =
        match crate::db_audit::lock_retention_sweep(pool, crate::db_audit::RETENTION_LOCK_WAIT)
            .await
        {
            Ok(l) => l,
            Err(e) => {
                return (
                    Err(e).context("take retention sweep lock"),
                    SweepNotes::default(),
                )
            }
        };
    let mut ctx = SweepCtx::new(policy);
    let result = prune_events_locked(
        pool,
        data_dir,
        retain_days,
        archive,
        batch,
        signing,
        &mut lock,
        after_batch,
        &mut ctx,
    )
    .await;
    release_lock(lock).await;
    let notes = ctx.io.notes;
    record_sweep_notes(pool, STREAM_EVENTS, &notes, result.is_ok()).await;
    (result, notes)
}

#[allow(clippy::too_many_arguments)]
async fn prune_events_locked(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    batch: i64,
    signing: Option<&SigningState>,
    lock: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    after_batch: AfterBatch<'_>,
    ctx: &mut SweepCtx,
) -> Result<usize> {
    let mut total = 0usize;
    check_floor(pool, retain_days).await?;
    if archive {
        tidy_archive(data_dir, &mut ctx.io.notes).await;
    }
    loop {
        let rows: Vec<EventRow> = sqlx::query_as::<_, EventRow>(
            r#"
            SELECT id, occurred_at, user_id, action, outcome, asset_id, checklist_id, stig_id,
                   source_ip, request_id, user_role, repeat_count, last_occurred_at,
                   detail::text AS detail
            FROM audit_events
            WHERE occurred_at < NOW() - ($1 || ' days')::INTERVAL
              AND (last_occurred_at IS NULL OR last_occurred_at < NOW() - ($1 || ' days')::INTERVAL)
            ORDER BY id ASC
            LIMIT $2
            "#,
        )
        .bind(retain_days.to_string())
        .bind(batch)
        .fetch_all(pool)
        .await
        .context("select expired audit_events rows")?;

        if rows.is_empty() {
            return Ok(total);
        }

        if archive {
            let lines = rows.iter().map(event_line).collect::<Result<Vec<_>>>()?;
            crate::db_audit::retention_lock_alive(lock).await?;
            archive_rows(data_dir, STREAM_EVENTS, lines, signing, ctx)
                .await
                .context("write audit events archive segment")?;
        }

        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        crate::db_audit::retention_lock_alive(lock).await?;
        let deleted = sqlx::query_scalar::<_, i64>("SELECT audit_prune_events($1::bigint[])")
            .bind(&ids)
            .fetch_one(pool)
            .await
            .context("delete pruned audit_events rows")? as usize;
        total += deleted;
        after_batch(total).await;
        if deleted == 0 || (rows.len() as i64) < batch {
            return Ok(total);
        }
    }
}

/// The scheduled audit retention body: prune `rule_audit` and `audit_events`
/// independently, so a failure in one never skips the other. Returns the
/// summary line; an error (naming both results) if either prune failed.
pub async fn run_scheduled(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
) -> Result<String> {
    run_scheduled_with(
        pool,
        data_dir,
        retain_days,
        archive,
        signing,
        DirSyncPolicy::from_env(),
    )
    .await
}

async fn run_scheduled_with(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
    policy: DirSyncPolicy,
) -> Result<String> {
    let (rules, mut notes) = run_prune_noted(
        pool,
        data_dir,
        retain_days,
        archive,
        signing,
        crate::db_audit::RETENTION_LOCK_WAIT,
        policy,
    )
    .await;
    let (events, event_notes) =
        run_prune_events_noted(pool, data_dir, retain_days, archive, signing, policy).await;
    notes.merge(event_notes);
    let suffix = notes_suffix(&notes);
    match (rules, events) {
        (Ok(n), Ok(e)) => Ok(format!(
            "pruned {n} rows and {e} events (retain_days={retain_days}, archive={archive}){suffix}"
        )),
        (r, e) => {
            let show = |x: Result<usize>| match x {
                Ok(n) => format!("pruned {n}"),
                Err(err) => format!("failed: {err:#}"),
            };
            anyhow::bail!(
                "audit retention: rule_audit {}; audit_events {}{suffix}",
                show(r),
                show(e)
            )
        }
    }
}

/// Scheduler-message suffix for what the sweeps set aside; empty when nothing.
fn notes_suffix(notes: &SweepNotes) -> String {
    let mut out = String::new();
    if notes.moved() > 0 {
        out.push_str(&format!("; archive files set aside: {}", notes.moved()));
    }
    if notes.failed_moves() > 0 {
        out.push_str(&format!("; archive moves FAILED: {}", notes.failed_moves()));
    }
    if notes.unsynced_publishes > 0 {
        out.push_str(&format!(
            "; DEGRADED durability: {} archive files published without a directory fsync ({ALLOW_UNSYNCED_DIR_ENV})",
            notes.unsynced_publishes
        ));
    }
    out
}

/// Detail of `audit_archive.file_set_aside`: at most `cap` files, failed
/// entries first; the totals count every entry.
fn set_aside_detail(sweep: &str, notes: &SweepNotes, cap: usize) -> serde_json::Value {
    let mut ordered: Vec<&SetAside> = notes.set_aside.iter().collect();
    ordered.sort_by_key(|s| s.error.is_none());
    let files: Vec<serde_json::Value> = ordered
        .iter()
        .take(cap)
        .map(|s| {
            let mut v = serde_json::json!({
                "from": s.from,
                "to": s.to,
                "reason": s.reason,
                "outcome": if s.error.is_none() { "moved" } else { "failed" },
            });
            if let (Some(err), Some(obj)) = (&s.error, v.as_object_mut()) {
                obj.insert("error".into(), serde_json::Value::String(err.clone()));
            }
            v
        })
        .collect();
    serde_json::json!({
        "sweep": sweep,
        "moved": notes.moved(),
        "failed": notes.failed_moves(),
        "truncated": ordered.len() > cap,
        "files": files,
    })
}

/// Detail of `audit_archive.durability_degraded`.
fn degraded_detail(sweep: &str, unsynced_publishes: u32, sweep_ok: bool) -> serde_json::Value {
    serde_json::json!({
        "sweep": sweep,
        "reason": "dir_fsync_unsupported",
        "unsynced_publishes": unsynced_publishes,
        "env_flag": ALLOW_UNSYNCED_DIR_ENV,
        "sweep_ok": sweep_ok,
    })
}

/// Record what a sweep set aside / relied on as system audit events. Called
/// after the sweep lock is released, on success and failure; nothing is
/// written when there is nothing to report. Best effort: the writes go through
/// the shared audit write queue and may be shed under load (logged on
/// failure); the scheduler message suffix and the `audit`-target log lines are
/// the fallback record.
async fn record_sweep_notes(
    pool: &PgPool,
    sweep: &'static str,
    notes: &SweepNotes,
    sweep_ok: bool,
) {
    if notes.is_empty() {
        return;
    }
    if !notes.set_aside.is_empty() {
        let failed = notes.failed_moves();
        if failed > 0 {
            tracing::error!(target: "audit", sweep, failed, "audit archive files could not be set aside");
        }
        crate::db_audit::record_system_or_log(
            pool,
            crate::db_audit::NewSystemEvent {
                action: "audit_archive.file_set_aside",
                outcome: if failed == 0 { "ok" } else { "partial" },
                stig_id: None,
                detail: set_aside_detail(sweep, notes, crate::db_audit::MAX_REJECTED_LISTED),
            },
        )
        .await;
    }
    if notes.unsynced_publishes > 0 {
        crate::db_audit::record_system_or_log(
            pool,
            crate::db_audit::NewSystemEvent {
                action: "audit_archive.durability_degraded",
                outcome: "partial",
                stig_id: None,
                detail: degraded_detail(sweep, notes.unsynced_publishes, sweep_ok),
            },
        )
        .await;
    }
}

fn event_line(row: &EventRow) -> Result<ArchiveLine> {
    let detail: serde_json::Value =
        serde_json::from_str(&row.detail).unwrap_or(serde_json::Value::Null);
    let line = serde_json::to_string(&serde_json::json!({
        "id": row.id,
        "occurred_at": row.occurred_at,
        "user_id": row.user_id,
        "action": row.action,
        "outcome": row.outcome,
        "asset_id": row.asset_id,
        "checklist_id": row.checklist_id,
        "stig_id": row.stig_id,
        "source_ip": row.source_ip,
        "request_id": row.request_id,
        "user_role": row.user_role,
        "repeat_count": row.repeat_count,
        "last_occurred_at": row.last_occurred_at,
        "detail": detail,
    }))
    .context("serialize audit event")?;
    Ok(ArchiveLine {
        id: row.id,
        occurred_at: row.occurred_at,
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::test_key;
    use crate::test_fixtures::seed_user;

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_rule_audit_deletes_and_archives_under_the_guard(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        for (rule, age) in [("old", "10 days"), ("new", "0 days")] {
            sqlx::query(&format!(
                "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
                 VALUES ('u1', 'c', $1, 'status', NOW() - INTERVAL '{age}')"
            ))
            .bind(rule)
            .execute(&pool)
            .await
            .unwrap();
        }
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        assert_eq!(run_prune(&pool, &dir, 5, true, None).await.unwrap(), 1);
        let left: Vec<String> = sqlx::query_scalar("SELECT rule_id FROM rule_audit")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["new"]);
        assert!(dir.join("audit_archive").exists());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_rule_audit_works_as_the_restricted_app_role(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        let app = crate::test_fixtures::app_role_pool(&pool, false).await;
        for (rule, age) in [("old", "10 days"), ("new", "0 days")] {
            sqlx::query(&format!(
                "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
                 VALUES ('u1', 'c', $1, 'status', NOW() - INTERVAL '{age}')"
            ))
            .bind(rule)
            .execute(&pool)
            .await
            .unwrap();
        }
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        assert_eq!(run_prune(&app.pool, &dir, 5, true, None).await.unwrap(), 1);
        let left: Vec<String> = sqlx::query_scalar("SELECT rule_id FROM rule_audit")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["new"]);
        app.cleanup(&pool).await;
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_sweep_below_the_floor_fails_before_archiving(pool: PgPool) {
        seed_user(&pool, "u1").await;
        crate::test_fixtures::set_audit_retention_floor(&pool, 365).await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'r', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let err = run_prune(&pool, &dir, 5, true, None).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("below the database retention floor"),
            "{err:#}"
        );
        assert!(!dir.exists(), "nothing may be archived");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        // The same holds for the events sweep.
        let err = run_prune_events(&pool, &dir, 5, true, None).await;
        assert!(err.is_err());
        assert!(!dir.exists());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_keys_on_the_last_repeat_and_archives_the_counter(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        // Both rows were first seen 10 days ago; only one was repeated recently.
        for (reason, last) in [("stale", "NOW() - INTERVAL '10 days'"), ("fresh", "NOW()")] {
            sqlx::query(&format!(
                "INSERT INTO audit_events (user_id, action, outcome, occurred_at, last_occurred_at, repeat_count, detail) \
                 VALUES ('u1', 'checklist.save', 'denied', NOW() - INTERVAL '10 days', {last}, 4, $1::jsonb)"
            ))
            .bind(format!("{{\"reason\":\"{reason}\"}}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events(&pool, &dir, 5, true, None).await.unwrap();
        assert_eq!(n, 1);
        let left: Vec<String> = sqlx::query_scalar("SELECT detail->>'reason' FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["fresh"]);
        let mut archived = String::new();
        for entry in std::fs::read_dir(dir.join("audit_archive")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                archived.push_str(&std::fs::read_to_string(path).unwrap());
            }
        }
        let line: serde_json::Value = serde_json::from_str(archived.trim()).unwrap();
        assert_eq!(line["repeat_count"], 4);
        assert!(line["last_occurred_at"].is_string());
        assert_eq!(line["detail"]["reason"], "stale");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_deletes_and_archives_only_expired_rows(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        for (outcome, days) in [("ok", 400), ("denied", 10)] {
            sqlx::query(
                "INSERT INTO audit_events (user_id, action, outcome, occurred_at, detail) \
                 VALUES ('u1', 'checklist.save', $1, NOW() - ($2 || ' days')::INTERVAL, '{\"k\":1}')",
            )
            .bind(outcome)
            .bind(days.to_string())
            .execute(&pool)
            .await
            .unwrap();
        }
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events(&pool, &dir, 365, true, None)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let left: Vec<String> = sqlx::query_scalar("SELECT outcome FROM audit_events")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["denied"]);
        let mut archived = String::new();
        for entry in std::fs::read_dir(dir.join("audit_archive")).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_name().to_string_lossy().starts_with("events-"));
            if entry.path().extension().is_some_and(|e| e == "jsonl") {
                archived.push_str(&std::fs::read_to_string(entry.path()).unwrap());
            }
        }
        let line: serde_json::Value = serde_json::from_str(archived.trim()).unwrap();
        assert_eq!(line["outcome"], "ok");
        assert_eq!(line["detail"]["k"], 1);
        // Without the archive switch nothing is written.
        let dir2 = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        assert_eq!(
            run_prune_events(&pool, &dir2, 5, false, None)
                .await
                .unwrap(),
            1
        );
        assert!(!dir2.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_archives_a_system_event_with_a_null_user(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        sqlx::query(
            "INSERT INTO audit_events (user_id, user_role, action, outcome, occurred_at, detail) \
             VALUES (NULL, 'system', 'catalog.sync', 'rejected', NOW() - INTERVAL '400 days', \
                     '{\"reasonCode\":\"download_too_large\"}')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events(&pool, &dir, 365, true, None)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let mut archived = String::new();
        for entry in std::fs::read_dir(dir.join("audit_archive")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                archived.push_str(&std::fs::read_to_string(path).unwrap());
            }
        }
        let line: serde_json::Value = serde_json::from_str(archived.trim()).unwrap();
        assert!(line["user_id"].is_null(), "{line}");
        assert_eq!(line["user_role"], "system");
        assert_eq!(line["action"], "catalog.sync");
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn seed_expired_event(pool: &PgPool, days: i64) {
        sqlx::query(
            "INSERT INTO audit_events (user_id, action, outcome, occurred_at) \
             VALUES ('u1', 'checklist.save', 'ok', NOW() - ($1 || ' days')::INTERVAL)",
        )
        .bind(days.to_string())
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_runs_in_batches_until_none_remain(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        for _ in 0..5 {
            seed_expired_event(&pool, 400).await;
        }
        seed_expired_event(&pool, 1).await;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events_batched(&pool, &dir, 365, true, 2, None)
            .await
            .unwrap();
        assert_eq!(n, 5);
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        let mut lines = 0;
        for seg in segments(&dir) {
            lines += std::fs::read_to_string(dir.join("audit_archive").join(seg))
                .unwrap()
                .lines()
                .count();
        }
        assert_eq!(lines, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn scheduled_run_prunes_expired_events_and_reports_them(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        seed_expired_event(&pool, 400).await;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let msg = run_scheduled(&pool, &dir, 365, false, None).await.unwrap();
        assert!(msg.contains("1 events"), "{msg}");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failing_rule_audit_prune_does_not_skip_the_event_prune(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        seed_expired_event(&pool, 400).await;
        sqlx::query("DROP TABLE rule_audit")
            .execute(&pool)
            .await
            .unwrap();
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let err = run_scheduled(&pool, &dir, 365, false, None)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("rule_audit failed") && msg.contains("audit_events pruned 1"),
            "{msg}"
        );
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
    }

    fn line(id: i64, date: &str) -> ArchiveLine {
        ArchiveLine {
            id,
            occurred_at: format!("{date}T12:00:00Z").parse().unwrap(),
            line: format!("{{\"id\":{id},\"v\":\"x\"}}"),
        }
    }

    fn segments(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir.join("audit_archive"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".jsonl"))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn segment_manifest_verifies_and_any_flipped_byte_fails() {
        let k = test_key(1);
        let dir = temp_dir();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(3, "2024-01-01"), line(1, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        let ad = dir.join("audit_archive");
        assert_eq!(segments(&dir), ["rules-2024-01-01.1-3.jsonl"]);
        let seg = "rules-2024-01-01.1-3.jsonl";
        assert_eq!(
            verify_segment(&ad, seg, Some(&k)).unwrap().status,
            SignatureStatus::Verified
        );
        // Flip a byte in the segment.
        let orig = std::fs::read(ad.join(seg)).unwrap();
        let mut bad = orig.clone();
        bad[2] ^= 1;
        std::fs::write(ad.join(seg), &bad).unwrap();
        assert!(verify_segment(&ad, seg, Some(&k)).is_err());
        std::fs::write(ad.join(seg), &orig).unwrap();
        // Rewrite the manifest's digest: the signature no longer covers it.
        let mp = ad.join(format!("{seg}.manifest.json"));
        let mut env: integrity::Envelope =
            serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
        let mut payload = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &env.payload,
        )
        .unwrap();
        let i = payload.iter().position(|&b| b == b'3').unwrap();
        payload[i] = b'4';
        env.payload =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &payload);
        std::fs::write(&mp, serde_json::to_vec(&env).unwrap()).unwrap();
        assert!(verify_segment(&ad, seg, Some(&k)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_a_key_the_manifest_carries_a_digest_only() {
        let dir = temp_dir();
        archive_blocking(
            &dir,
            STREAM_EVENTS,
            vec![line(5, "2024-02-02")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        let ad = dir.join("audit_archive");
        let seg = "events-2024-02-02.5-5.jsonl";
        assert_eq!(
            verify_segment(&ad, seg, None).unwrap().status,
            SignatureStatus::Unsigned
        );
        let sidecar: serde_json::Value = serde_json::from_slice(
            &std::fs::read(ad.join(format!("{seg}.manifest.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(sidecar["signatures"], serde_json::json!([]));
        // There is no unauthenticated copy of the manifest next to the payload.
        assert!(sidecar.get("manifest").is_none());
        let payload = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sidecar["payload"].as_str().unwrap(),
        )
        .unwrap();
        let m: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(m["digest"]["algorithm"], "sha-512");
        assert_eq!(m["signers"], serde_json::json!([]));
        let mut bad = std::fs::read(ad.join(seg)).unwrap();
        bad[2] ^= 1;
        std::fs::write(ad.join(seg), bad).unwrap();
        assert!(verify_segment(&ad, seg, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_run_over_the_same_rows_writes_nothing() {
        let k = test_key(1);
        let dir = temp_dir();
        let rows = || {
            vec![
                line(1, "2024-01-01"),
                line(2, "2024-01-01"),
                line(9, "2024-01-02"),
            ]
        };
        archive_blocking(
            &dir,
            STREAM_RULES,
            rows(),
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        let before = std::fs::read_dir(dir.join("audit_archive"))
            .unwrap()
            .count();
        archive_blocking(
            &dir,
            STREAM_RULES,
            rows(),
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_dir(dir.join("audit_archive"))
                .unwrap()
                .count(),
            before
        );
        // A partial overlap writes only the new id, as its own segment.
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(2, "2024-01-01"), line(7, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert_eq!(
            segments(&dir),
            [
                "rules-2024-01-01.1-2.jsonl",
                "rules-2024-01-01.7-7.jsonl",
                "rules-2024-01-02.9-9.jsonl"
            ]
        );
        // No temp files linger.
        assert!(std::fs::read_dir(dir.join("audit_archive"))
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_append_files_are_left_alone_and_never_trusted_to_skip_a_row() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let legacy = "{\"id\":1,\"v\":\"old\"}\n{\"id\":2,\"v\":\"old\"}\n";
        std::fs::write(ad.join("2024-01-01.jsonl"), legacy).unwrap();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(2, "2024-01-01"), line(3, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(ad.join("2024-01-01.jsonl")).unwrap(),
            legacy
        );
        assert!(ad.join("rules-2024-01-01.2-3.jsonl").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_planted_segment_does_not_stop_its_ids_being_archived() {
        let k = test_key(1);
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        // Claims id 5, has no sidecar.
        std::fs::write(ad.join("rules-2024-01-01.1-1.jsonl"), "{\"id\":5}\n").unwrap();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        let seg = "rules-2024-01-01.5-5.jsonl";
        assert_eq!(
            verify_segment(&ad, seg, Some(&k)).unwrap().status,
            SignatureStatus::Verified
        );
        // A planted segment with a forged, digest-only sidecar is rejected too when a key is set.
        let forged = temp_dir();
        archive_blocking(
            &forged,
            STREAM_RULES,
            vec![line(6, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        for f in [
            "rules-2024-01-01.6-6.jsonl",
            "rules-2024-01-01.6-6.jsonl.manifest.json",
        ] {
            std::fs::copy(forged.join("audit_archive").join(f), ad.join(f)).unwrap();
        }
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(6, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        // The unsigned segment is left in place; a signed sibling holds the row.
        assert_eq!(
            verify_segment(&ad, "rules-2024-01-01.6-6.r1.jsonl", Some(&k))
                .unwrap()
                .status,
            SignatureStatus::Verified
        );
        // Only the sidecar-less plant from the first step was quarantined.
        assert_eq!(rejected(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&forged);
    }

    #[test]
    fn a_segment_missing_its_sidecar_or_tampered_is_archived_again() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(1, "2024-01-01"), line(2, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        let seg = "rules-2024-01-01.1-2.jsonl";
        let side = ad.join(format!("{seg}.manifest.json"));
        // No sidecar: rewritten (same name, replaced) with a sidecar.
        std::fs::remove_file(&side).unwrap();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(1, "2024-01-01"), line(2, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert!(verify_segment(&ad, seg, None).is_ok());
        assert_eq!(
            rejected(&dir).len(),
            1,
            "the sidecar-less segment is preserved"
        );
        // Tampered (drops id 2, keeps a valid line shape): re-archived from the rows.
        std::fs::write(
            ad.join(seg),
            "{\"id\":1,\"v\":\"x\"}\n{\"id\":2,\"v\":\"evil\"}\n",
        )
        .unwrap();
        assert!(verify_segment(&ad, seg, None).is_err());
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(1, "2024-01-01"), line(2, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert!(verify_segment(&ad, seg, None).is_ok());
        assert!(!std::fs::read_to_string(ad.join(seg))
            .unwrap()
            .contains("evil"));
        // A segment whose ids fall outside its name's range is not trusted.
        std::fs::write(ad.join("rules-2024-01-01.9-9.jsonl"), "{\"id\":10}\n").unwrap();
        assert!(verify_segment(&ad, "rules-2024-01-01.9-9.jsonl", None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn rejected(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir.join("audit_archive"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".rejected-"))
            .collect();
        v.sort();
        v
    }

    /// Copy every file of `from`'s archive into `to`'s.
    fn plant(from: &Path, to: &Path) {
        let dst = to.join("audit_archive");
        std::fs::create_dir_all(&dst).unwrap();
        for e in std::fs::read_dir(from.join("audit_archive")).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), dst.join(e.file_name())).unwrap();
        }
    }

    fn ad_has(dir: &Path, name: &str) -> bool {
        dir.join("audit_archive").join(name).exists()
    }

    fn forged_line(id: i64, date: &str) -> ArchiveLine {
        ArchiveLine {
            line: format!("{{\"id\":{id},\"v\":\"FORGED\"}}"),
            ..line(id, date)
        }
    }

    #[test]
    fn a_planted_self_consistent_segment_cannot_hide_a_real_row() {
        // No signing key: a forged line with a matching digest sidecar.
        let (dir, forged) = (temp_dir(), temp_dir());
        archive_blocking(
            &forged,
            STREAM_RULES,
            vec![forged_line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        plant(&forged, &dir);
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        let ad = dir.join("audit_archive");
        // The forged segment is left untouched and still verifies; the real
        // line is in a non-colliding sibling.
        let forged_seg = verify_segment(&ad, "rules-2024-01-01.5-5.jsonl", None).unwrap();
        assert!(String::from_utf8(forged_seg.body)
            .unwrap()
            .contains("FORGED"));
        let real = verify_segment(&ad, "rules-2024-01-01.5-5.r1.jsonl", None).unwrap();
        assert!(String::from_utf8(real.body).unwrap().contains("\"x\""));
        assert!(rejected(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&forged);
    }

    #[test]
    fn a_planted_segment_holding_the_genuine_line_is_skipped() {
        let (dir, genuine) = (temp_dir(), temp_dir());
        archive_blocking(
            &genuine,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        plant(&genuine, &dir);
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert_eq!(segments(&dir), ["rules-2024-01-01.5-5.jsonl"]);
        assert!(rejected(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&genuine);
    }

    #[test]
    fn an_unknown_key_segment_is_rearchived_with_a_key_and_matched_by_line_without_one() {
        let (a, b) = (test_key(1), test_key(2));
        let (dir, other) = (temp_dir(), temp_dir());
        archive_blocking(
            &other,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            Some(&a),
            &mut SweepCtx::default(),
        )
        .unwrap();
        plant(&other, &dir);
        // No key here: signed by another key, so it cannot be checked, but the line matches.
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert!(rejected(&dir).is_empty());
        // No key, different line: archived.
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![forged_line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert!(ad_has(&dir, "rules-2024-01-01.5-5.r1.jsonl"));
        // With key B the key-A segment is unknown_key: rejected and rewritten, verified.
        let (dir2, other2) = (temp_dir(), temp_dir());
        archive_blocking(
            &other2,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            Some(&a),
            &mut SweepCtx::default(),
        )
        .unwrap();
        plant(&other2, &dir2);
        archive_blocking(
            &dir2,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            Some(&b),
            &mut SweepCtx::default(),
        )
        .unwrap();
        // Nothing is renamed; the key-A segment stays, and the row lands in a sibling.
        assert!(rejected(&dir2).is_empty());
        assert_eq!(
            verify_segment(
                &dir2.join("audit_archive"),
                "rules-2024-01-01.5-5.r1.jsonl",
                Some(&b)
            )
            .unwrap()
            .status,
            SignatureStatus::Verified
        );
        assert!(ad_has(&dir2, "rules-2024-01-01.5-5.jsonl"));
        for d in [dir, other, dir2, other2] {
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn rejected_files_are_never_counted_as_archived() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        std::fs::write(
            ad.join("rules-2024-01-01.5-5.jsonl.rejected-20240101T000000.000Z"),
            "{\"id\":5}\n",
        )
        .unwrap();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert_eq!(segments(&dir), ["rules-2024-01-01.5-5.jsonl"]);
    }

    #[test]
    fn a_transient_read_error_leaves_the_segment_in_place_and_uncounted() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        // A directory under the segment's name: reading it is an I/O error.
        std::fs::create_dir_all(ad.join("rules-2024-01-01.5-5.jsonl")).unwrap();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert!(ad.join("rules-2024-01-01.5-5.jsonl").is_dir());
        assert!(rejected(&dir).is_empty());
        assert!(verify_segment(&ad, "rules-2024-01-01.5-5.r1.jsonl", None).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn after_a_key_is_added_an_unsigned_segment_is_left_and_its_rows_rearchived_beside_it() {
        let k = test_key(1);
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut SweepCtx::default(),
        )
        .unwrap();
        let before = std::fs::read(ad.join("rules-2024-01-01.5-5.jsonl")).unwrap();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert!(rejected(&dir).is_empty());
        assert_eq!(
            std::fs::read(ad.join("rules-2024-01-01.5-5.jsonl")).unwrap(),
            before
        );
        assert_eq!(
            verify_segment(&ad, "rules-2024-01-01.5-5.r1.jsonl", Some(&k))
                .unwrap()
                .status,
            SignatureStatus::Verified
        );
        // A further sweep under the key finds the signed sibling and writes nothing.
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert_eq!(segments(&dir).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rewrite_with_the_same_id_range_as_a_verified_segment_goes_to_an_r_file() {
        let k = test_key(1);
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(1, "2024-01-01"), line(3, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        let orig = "rules-2024-01-01.1-3.jsonl";
        let before = std::fs::read(ad.join(orig)).unwrap();
        // Rows 1 and 3 now have different lines: same first and last id.
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![forged_line(1, "2024-01-01"), forged_line(3, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert_eq!(std::fs::read(ad.join(orig)).unwrap(), before);
        assert_eq!(
            verify_segment(&ad, orig, Some(&k)).unwrap().status,
            SignatureStatus::Verified
        );
        assert_eq!(
            verify_segment(&ad, "rules-2024-01-01.1-3.r1.jsonl", Some(&k))
                .unwrap()
                .status,
            SignatureStatus::Verified
        );
        assert!(rejected(&dir).is_empty());
        // The `.rN` form parses, and a bad suffix does not.
        assert_eq!(
            segment_range("rules-2024-01-01.1-3.r12.jsonl", "rules", "2024-01-01"),
            Some((1, 3))
        );
        assert_eq!(
            segment_range("rules-2024-01-01.1-3.x1.jsonl", "rules", "2024-01-01"),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_delete_followed_by_a_retry_archives_each_id_once(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        let k = test_key(1);
        for rule in ["a", "b"] {
            sqlx::query(
                "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
                 VALUES ('u1', 'c', $1, 'status', NOW() - INTERVAL '10 days')",
            )
            .bind(rule)
            .execute(&pool)
            .await
            .unwrap();
        }
        let rows: Vec<(i64, DateTime<Utc>)> =
            sqlx::query_as("SELECT id, occurred_at FROM rule_audit ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        let ids: Vec<i64> = rows.iter().map(|r| r.0).collect();
        let dir = temp_dir();
        assert_eq!(run_prune(&pool, &dir, 5, true, Some(&k)).await.unwrap(), 2);
        // Put the rows back under their ids: as if the delete had failed after the archive was written.
        for ((id, at), rule) in rows.iter().zip(["a", "b"]) {
            sqlx::query(
                "INSERT INTO rule_audit (id, user_id, checklist_id, rule_id, field, occurred_at) \
                 VALUES ($1, 'u1', 'c', $2, 'status', $3)",
            )
            .bind(id)
            .bind(rule)
            .bind(at)
            .execute(&pool)
            .await
            .unwrap();
        }
        assert_eq!(run_prune(&pool, &dir, 5, true, Some(&k)).await.unwrap(), 2);
        let mut seen = Vec::new();
        for seg in segments(&dir) {
            assert_eq!(
                verify_segment(&dir.join("audit_archive"), &seg, Some(&k))
                    .unwrap()
                    .status,
                SignatureStatus::Verified
            );
            seen.extend(
                lines_in(&std::fs::read(dir.join("audit_archive").join(&seg)).unwrap())
                    .unwrap()
                    .into_iter()
                    .map(|(i, _)| i),
            );
        }
        seen.sort();
        assert_eq!(seen, ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_archive_write_deletes_nothing(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'a', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        // `audit_archive` is a file, so no segment can be written.
        std::fs::write(dir.join("audit_archive"), b"not a directory").unwrap();
        assert!(run_prune(&pool, &dir, 5, true, None).await.is_err());
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn arm_dir_sync_failure_kind(dir: &Path, kind: std::io::ErrorKind) {
        FAIL_DIR_SYNC
            .lock()
            .unwrap()
            .push((dir.to_path_buf(), kind));
    }

    fn arm_dir_sync_failure(dir: &Path) {
        arm_dir_sync_failure_kind(dir, std::io::ErrorKind::Other);
    }

    fn disarm_dir_sync_failure(dir: &Path) {
        FAIL_DIR_SYNC.lock().unwrap().retain(|(p, _)| p != dir);
    }

    fn entries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn dir_sync_policy_parses_only_true_or_1() {
        for on in ["true", "TRUE ", "1"] {
            assert_eq!(
                DirSyncPolicy::from_raw(Some(on)),
                DirSyncPolicy::TolerateUnsupported,
                "{on:?}"
            );
        }
        for off in [None, Some(""), Some("yes"), Some("0")] {
            assert_eq!(DirSyncPolicy::from_raw(off), DirSyncPolicy::FailClosed);
        }
    }

    #[test]
    fn dir_sync_fatality_truth_table() {
        use std::io::{Error, ErrorKind};
        use DirSyncPolicy::{FailClosed, TolerateUnsupported};
        for kind in [ErrorKind::InvalidInput, ErrorKind::Unsupported] {
            assert!(dir_sync_is_fatal(&Error::from(kind), FailClosed));
            assert!(!dir_sync_is_fatal(&Error::from(kind), TolerateUnsupported));
        }
        for kind in [
            ErrorKind::Other,
            ErrorKind::PermissionDenied,
            ErrorKind::StorageFull,
        ] {
            assert!(dir_sync_is_fatal(&Error::from(kind), FailClosed));
            assert!(dir_sync_is_fatal(&Error::from(kind), TolerateUnsupported));
        }
    }

    #[test]
    fn an_unsupported_directory_sync_fails_closed_by_default() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let rows = [line(1, "2024-01-01")];
        let group: Vec<&ArchiveLine> = rows.iter().collect();
        arm_dir_sync_failure_kind(&ad, std::io::ErrorKind::InvalidInput);
        let mut io = ArchiveIo::default();
        let res = write_segment(&ad, STREAM_RULES, "2024-01-01", &group, None, &mut io);
        disarm_dir_sync_failure(&ad);
        let err = res.unwrap_err();
        assert!(
            format!("{err:#}").contains(ALLOW_UNSYNCED_DIR_ENV),
            "{err:#}"
        );
        assert!(entries(&ad).is_empty());
        assert_eq!(io.notes.unsynced_publishes, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sidecar_directory_sync_failure_aborts_and_leaves_nothing() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let rows = [line(1, "2024-01-01")];
        let group: Vec<&ArchiveLine> = rows.iter().collect();
        arm_dir_sync_failure(&ad);
        let err = write_segment(
            &ad,
            STREAM_RULES,
            "2024-01-01",
            &group,
            None,
            &mut ArchiveIo::default(),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("sync directory after publishing"));
        assert!(entries(&ad).is_empty());
        disarm_dir_sync_failure(&ad);
        write_segment(
            &ad,
            STREAM_RULES,
            "2024-01-01",
            &group,
            None,
            &mut ArchiveIo::default(),
        )
        .unwrap();
        assert_eq!(segments(&dir), ["rules-2024-01-01.1-1.jsonl"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn a_tolerated_directory_sync_error_still_publishes() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let rows = [line(1, "2024-01-01")];
        let group: Vec<&ArchiveLine> = rows.iter().collect();
        arm_dir_sync_failure_kind(&ad, std::io::ErrorKind::InvalidInput);
        let mut io = ArchiveIo {
            policy: DirSyncPolicy::TolerateUnsupported,
            ..ArchiveIo::default()
        };
        let res = write_segment(&ad, STREAM_RULES, "2024-01-01", &group, None, &mut io);
        disarm_dir_sync_failure(&ad);
        res.unwrap();
        assert_eq!(segments(&dir), ["rules-2024-01-01.1-1.jsonl"]);
        assert_eq!(io.notes.unsynced_publishes, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_segment_directory_sync_failure_aborts_and_leaves_nothing() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let rows = [line(1, "2024-01-01")];
        let group: Vec<&ArchiveLine> = rows.iter().collect();
        let res = write_segment_with(
            &ad,
            STREAM_RULES,
            "2024-01-01",
            &group,
            None,
            &|stage, _| {
                if stage == WriteStage::SidecarPublished {
                    arm_dir_sync_failure(&ad);
                }
                Ok(())
            },
            &mut ArchiveIo::default(),
        );
        disarm_dir_sync_failure(&ad);
        assert!(res.is_err());
        assert!(entries(&ad).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_directory_sync_deletes_nothing(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'a', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        arm_dir_sync_failure(&ad);
        assert!(run_prune(&pool, &dir, 5, true, None).await.is_err());
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        disarm_dir_sync_failure(&ad);
        run_prune(&pool, &dir, 5, true, None).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
        assert_eq!(segments(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scan_between_sidecar_and_segment_quarantines_nothing() {
        let k = test_key(1);
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let rows = [line(1, "2024-01-01"), line(2, "2024-01-01")];
        let group: Vec<&ArchiveLine> = rows.iter().collect();
        write_segment_with(
            &ad,
            STREAM_RULES,
            "2024-01-01",
            &group,
            Some(&k),
            &|stage, _| {
                if stage == WriteStage::SidecarPublished {
                    archived_lines(
                        &ad,
                        STREAM_RULES,
                        "2024-01-01",
                        Some(&k),
                        &mut SweepNotes::default(),
                    )
                    .unwrap();
                    assert!(rejected(&dir).is_empty());
                }
                Ok(())
            },
            &mut ArchiveIo::default(),
        )
        .unwrap();
        assert!(rejected(&dir).is_empty());
        let seen = archived_lines(
            &ad,
            STREAM_RULES,
            "2024-01-01",
            Some(&k),
            &mut SweepNotes::default(),
        )
        .unwrap();
        assert!(seen.contains_key(&1) && seen.contains_key(&2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_orphan_sidecar_is_ignored_and_the_next_write_takes_an_r_name() {
        let k = test_key(1);
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let orphan = ad.join("rules-2024-01-01.1-2.jsonl.manifest.json");
        std::fs::write(&orphan, b"orphan").unwrap();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(1, "2024-01-01"), line(2, "2024-01-01")],
            Some(&k),
            &mut SweepCtx::default(),
        )
        .unwrap();
        assert!(rejected(&dir).is_empty());
        assert_eq!(std::fs::read(&orphan).unwrap(), b"orphan");
        assert_eq!(segments(&dir), ["rules-2024-01-01.1-2.r1.jsonl"]);
        assert!(verify_segment(&ad, "rules-2024-01-01.1-2.r1.jsonl", Some(&k)).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_sweep_waits_for_the_lock_and_touches_nothing_until_it_is_free(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        use crate::test_fixtures::app_role_pool;
        seed_user(&pool, "u1").await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'old', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let app = app_role_pool(&pool, false).await;
        let k = test_key(1);
        let dir = temp_dir();
        let lock =
            crate::db_audit::lock_retention_sweep(&app.pool, crate::db_audit::RETENTION_LOCK_WAIT)
                .await
                .unwrap();
        let task = {
            let (p, d, k) = (app.pool.clone(), dir.clone(), k.clone());
            tokio::spawn(async move { run_prune(&p, &d, 5, true, Some(&k)).await })
        };
        let mut waiting = 0i64;
        for _ in 0..600 {
            waiting = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            waiting, 1,
            "the sweep never queued on the advisory lock within 30 s"
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        assert!(!dir.join("audit_archive").exists());
        lock.rollback().await.unwrap();
        assert_eq!(task.await.unwrap().unwrap(), 1);
        assert!(rejected(&dir).is_empty());
        for s in segments(&dir) {
            assert!(verify_segment(&dir.join("audit_archive"), &s, Some(&k)).is_ok());
        }
        assert_eq!(segments(&dir).len(), 1);
        app.cleanup(&pool).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_event_sweeps_lose_no_row_and_reject_no_segment(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        for _ in 0..25 {
            seed_expired_event(&pool, 10).await;
        }
        let seeded: Vec<i64> = sqlx::query_scalar("SELECT id FROM audit_events ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        // Serialization itself is shown by the lock-wait test; this one covers
        // the outcome: no duplicate, no lost row, no quarantined segment.
        let k = test_key(1);
        let dir = temp_dir();
        let (a, b) = tokio::join!(
            run_prune_events_batched(&pool, &dir, 5, true, 4, Some(&k)),
            run_prune_events_batched(&pool, &dir, 5, true, 4, Some(&k)),
        );
        assert_eq!(a.unwrap() + b.unwrap(), 25);
        assert!(rejected(&dir).is_empty());
        let ad = dir.join("audit_archive");
        let mut ids = Vec::new();
        for s in segments(&dir) {
            let v = verify_segment(&ad, &s, Some(&k)).unwrap();
            assert_eq!(v.status, SignatureStatus::Verified);
            ids.extend(lines_in(&v.body).unwrap().into_iter().map(|(id, _)| id));
        }
        ids.sort();
        assert_eq!(ids, seeded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_sweep_gives_up_on_a_held_lock_and_deletes_nothing(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        use crate::test_fixtures::app_role_pool;
        seed_user(&pool, "u1").await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'old', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let app = app_role_pool(&pool, false).await;
        let dir = temp_dir();
        let lock =
            crate::db_audit::lock_retention_sweep(&app.pool, crate::db_audit::RETENTION_LOCK_WAIT)
                .await
                .unwrap();
        let err = run_prune_noted(
            &app.pool,
            &dir,
            5,
            true,
            None,
            std::time::Duration::from_millis(300),
            DirSyncPolicy::default(),
        )
        .await
        .0
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("another retention sweep holds the lock"),
            "{err:#}"
        );
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        assert!(!dir.join("audit_archive").exists());
        lock.rollback().await.unwrap();
        app.cleanup(&pool).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_lost_lock_stops_the_sweep_with_every_deleted_row_already_archived(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        for _ in 0..25 {
            seed_expired_event(&pool, 10).await;
        }
        let seeded: Vec<i64> = sqlx::query_scalar("SELECT id FROM audit_events ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        let k = test_key(1);
        let dir = temp_dir();
        // After the first committed batch, kill the backend holding the lock.
        let admin = pool.clone();
        let hook = move |batch_total: usize| -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            let admin = admin.clone();
            Box::pin(async move {
                if batch_total != 4 {
                    return;
                }
                kill_retention_lock_holder(&admin).await;
            })
        };
        let err = run_prune_events_with(
            &pool,
            &dir,
            5,
            true,
            4,
            Some(&k),
            &hook,
            DirSyncPolicy::default(),
        )
        .await
        .0
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("retention sweep lock lost"),
            "{err:#}"
        );
        let remaining: Vec<i64> = sqlx::query_scalar("SELECT id FROM audit_events ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(remaining.len(), 21, "only the first batch may be deleted");
        assert!(rejected(&dir).is_empty());
        let ad = dir.join("audit_archive");
        let mut archived = Vec::new();
        for s in segments(&dir) {
            let v = verify_segment(&ad, &s, Some(&k)).unwrap();
            assert_eq!(v.status, SignatureStatus::Verified);
            archived.extend(lines_in(&v.body).unwrap().into_iter().map(|(id, _)| id));
        }
        for id in seeded.iter().filter(|id| !remaining.contains(id)) {
            assert!(archived.contains(id), "deleted id {id} is not archived");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Terminate the backend holding the retention sweep advisory lock (found
    /// by key, in this database) and wait until it is gone.
    async fn kill_retention_lock_holder(admin: &PgPool) {
        let pid: i32 = sqlx::query_scalar(
            "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 1 \
             AND ((classid::bigint << 32) | objid::bigint) = $1 \
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .bind(crate::db_audit::RETENTION_SWEEP_LOCK)
        .fetch_one(admin)
        .await
        .unwrap();
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(admin)
            .await
            .unwrap();
        for _ in 0..200 {
            let alive: i64 =
                sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE pid = $1")
                    .bind(pid)
                    .fetch_one(admin)
                    .await
                    .unwrap();
            if alive == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("lock backend {pid} did not terminate");
    }

    /// Run a `run_prune` sweep that is blocked on its `SELECT` by an ACCESS
    /// EXCLUSIVE table lock, kill its lock backend, release the table and
    /// return the sweep's error text.
    async fn lose_lock_during_rules_select(
        pool: &PgPool,
        archive: bool,
    ) -> (String, std::path::PathBuf) {
        seed_user(pool, "u1").await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'old', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(pool)
        .await
        .unwrap();
        let dir = temp_dir();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE rule_audit IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let task = {
            let (p, d) = (pool.clone(), dir.clone());
            tokio::spawn(async move { run_prune(&p, &d, 5, archive, None).await })
        };
        // Wait until the sweep holds the advisory lock and queues on the table.
        let mut ready = false;
        for _ in 0..600 {
            let queued: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'relation' AND NOT granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
            )
            .fetch_one(pool)
            .await
            .unwrap();
            if queued >= 1 {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(ready, "the sweep never blocked on the table lock");
        kill_retention_lock_holder(pool).await;
        blocker.commit().await.unwrap();
        let err = task.await.unwrap().unwrap_err();
        (format!("{err:#}"), dir)
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_lost_lock_stops_the_rules_sweep_before_anything_is_archived(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        let (err, dir) = lose_lock_during_rules_select(&pool, true).await;
        assert!(err.contains("retention sweep lock lost"), "{err}");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        assert!(!dir.join("audit_archive").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_lost_lock_stops_the_rules_sweep_before_the_delete(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        let (err, dir) = lose_lock_during_rules_select(&pool, false).await;
        assert!(err.contains("retention sweep lock lost"), "{err}");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rule_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn concurrent_rule_sweeps_lose_no_row_and_reject_no_segment(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        for _ in 0..25 {
            sqlx::query(
                "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
                 VALUES ('u1', 'c', 'old', 'status', NOW() - INTERVAL '10 days')",
            )
            .execute(&pool)
            .await
            .unwrap();
        }
        let seeded: Vec<i64> = sqlx::query_scalar("SELECT id FROM rule_audit ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        let k = test_key(1);
        let dir = temp_dir();
        let (a, b) = tokio::join!(
            run_prune(&pool, &dir, 5, true, Some(&k)),
            run_prune(&pool, &dir, 5, true, Some(&k)),
        );
        assert_eq!(a.unwrap() + b.unwrap(), 25);
        assert!(rejected(&dir).is_empty());
        let ad = dir.join("audit_archive");
        let mut ids = Vec::new();
        for s in segments(&dir) {
            let v = verify_segment(&ad, &s, Some(&k)).unwrap();
            assert_eq!(v.status, SignatureStatus::Verified);
            ids.extend(lines_in(&v.body).unwrap().into_iter().map(|(id, _)| id));
        }
        ids.sort();
        assert_eq!(ids, seeded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_retention_delete_without_the_protocol_marker_is_refused(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_user(&pool, "u1").await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'old', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(&pool)
        .await
        .unwrap();
        // An older replica: retention mode but no protocol marker.
        let mut tx = pool.begin().await.unwrap();
        crate::db_audit::set_maintenance(&mut tx, "retention")
            .await
            .unwrap();
        let err = sqlx::query("DELETE FROM rule_audit")
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(
            err.as_database_error().and_then(|d| d.code()).as_deref(),
            Some("42501")
        );
        drop(tx);
        let mut tx = pool.begin().await.unwrap();
        declare_retention_delete(&mut tx).await.unwrap();
        let n = sqlx::query("DELETE FROM rule_audit")
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected();
        tx.commit().await.unwrap();
        assert_eq!(n, 1);
    }

    fn one_group_write(
        dir: &Path,
        lines: &[ArchiveLine],
        hook: &dyn Fn(WriteStage, &str) -> Result<()>,
    ) -> Result<()> {
        let group: Vec<&ArchiveLine> = lines.iter().collect();
        write_segment_with(
            dir,
            STREAM_RULES,
            "2024-01-01",
            &group,
            None,
            hook,
            &mut ArchiveIo::default(),
        )
    }

    #[test]
    fn publishing_an_existing_name_is_refused_and_leaves_it_untouched() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            publish_new(&dir, "a.jsonl", b"first", &mut ArchiveIo::default()).unwrap(),
            Publish::Created
        );
        assert_eq!(
            publish_new(&dir, "a.jsonl", b"second", &mut ArchiveIo::default()).unwrap(),
            Publish::Taken
        );
        assert_eq!(std::fs::read(dir.join("a.jsonl")).unwrap(), b"first");
        assert_eq!(entries(&dir), ["a.jsonl"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_sweeps_picking_the_same_name_publish_two_intact_pairs() {
        let k = test_key(1);
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let a_rows = [line(1, "2024-01-01"), line(2, "2024-01-01")];
        let mut b_rows = [line(1, "2024-01-01"), line(2, "2024-01-01")];
        b_rows[0].line.push(' ');
        let ran = std::cell::Cell::new(false);
        let a: Vec<&ArchiveLine> = a_rows.iter().collect();
        let b: Vec<&ArchiveLine> = b_rows.iter().collect();
        write_segment_with(
            &ad,
            STREAM_RULES,
            "2024-01-01",
            &a,
            Some(&k),
            &|stage, _| {
                if stage == WriteStage::NamePicked && !ran.replace(true) {
                    write_segment_with(
                        &ad,
                        STREAM_RULES,
                        "2024-01-01",
                        &b,
                        Some(&k),
                        &|_, _| Ok(()),
                        &mut ArchiveIo::default(),
                    )?;
                }
                Ok(())
            },
            &mut ArchiveIo::default(),
        )
        .unwrap();
        assert_eq!(
            segments(&dir),
            [
                "rules-2024-01-01.1-2.jsonl",
                "rules-2024-01-01.1-2.r1.jsonl"
            ]
        );
        for s in segments(&dir) {
            assert!(verify_segment(&ad, &s, Some(&k)).is_ok());
        }
        assert!(
            String::from_utf8(std::fs::read(ad.join("rules-2024-01-01.1-2.jsonl")).unwrap())
                .unwrap()
                .contains(" \n")
        );
        assert!(rejected(&dir).is_empty());
        assert!(entries(&ad).iter().all(|n| !n.ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn racing_writers_never_replace_each_other() {
        let k = test_key(1);
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|sc| {
            for i in 0..8 {
                let (ad, k, barrier) = (&ad, &k, &barrier);
                sc.spawn(move || {
                    let mut rows = [line(1, "2024-01-01"), line(2, "2024-01-01")];
                    rows[0].line.push_str(&" ".repeat(i));
                    let group: Vec<&ArchiveLine> = rows.iter().collect();
                    barrier.wait();
                    write_segment(
                        ad,
                        STREAM_RULES,
                        "2024-01-01",
                        &group,
                        Some(k),
                        &mut ArchiveIo::default(),
                    )
                    .unwrap();
                });
            }
        });
        let segs = segments(&dir);
        assert_eq!(segs.len(), 8);
        for s in &segs {
            assert!(verify_segment(&ad, s, Some(&k)).is_ok());
        }
        assert!(rejected(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_segment_write_removes_the_sidecar_it_just_published() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let rows = [line(1, "2024-01-01")];
        let err = one_group_write(&ad, &rows, &|stage, name| {
            if stage == WriteStage::SidecarPublished {
                assert!(ad.join(format!("{name}.manifest.json")).exists());
                std::fs::write(ad.join(name), b"planted")?;
            }
            Ok(())
        })
        .unwrap_err();
        assert!(
            err.chain()
                .filter_map(|e| e.downcast_ref::<std::io::Error>())
                .any(|e| e.kind() == std::io::ErrorKind::AlreadyExists),
            "{err:#}"
        );
        assert_eq!(entries(&ad), ["rules-2024-01-01.1-1.jsonl"]);
        assert_eq!(
            std::fs::read(ad.join("rules-2024-01-01.1-1.jsonl")).unwrap(),
            b"planted"
        );
        assert!(rejected(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_old_orphan_sidecar_is_set_aside_and_its_name_is_free_again() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let name = "rules-2024-01-01.1-2.jsonl.manifest.json";
        std::fs::write(dir.join(name), b"orphan").unwrap();
        assert_eq!(set_aside_orphan_sidecars(&dir, Duration::ZERO).len(), 1);
        assert!(!dir.join(name).exists());
        let left = entries(&dir);
        assert_eq!(left.len(), 1);
        assert!(left[0].starts_with(&format!("{name}.orphan-")), "{left:?}");
        assert_eq!(std::fs::read(dir.join(&left[0])).unwrap(), b"orphan");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fresh_orphan_sidecar_is_left_alone() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let name = "events-2024-01-01.1-2.jsonl.manifest.json";
        std::fs::write(dir.join(name), b"orphan").unwrap();
        assert_eq!(
            set_aside_orphan_sidecars(&dir, ORPHAN_SIDECAR_MIN_AGE).len(),
            0
        );
        assert_eq!(entries(&dir), [name]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sidecar_with_its_segment_and_foreign_files_are_never_set_aside() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        for n in [
            "rules-2024-01-01.1-2.jsonl",
            "rules-2024-01-01.1-2.jsonl.manifest.json",
            "notes.manifest.json",
            "other-2024-01-01.1-2.jsonl.manifest.json",
            "rules-2024-01-01.1-2.jsonl.rejected-x",
        ] {
            std::fs::write(dir.join(n), b"x").unwrap();
        }
        let before = entries(&dir);
        assert_eq!(set_aside_orphan_sidecars(&dir, Duration::ZERO).len(), 0);
        assert_eq!(entries(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn age_file(path: &Path, hours: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(std::time::SystemTime::now() - Duration::from_secs(hours * 3600))
            .unwrap();
    }

    #[test]
    fn the_orphan_age_threshold_is_24_hours() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let young = "rules-2024-01-01.1-2.jsonl.manifest.json";
        let old = "rules-2024-01-01.3-4.jsonl.manifest.json";
        std::fs::write(dir.join(young), b"y").unwrap();
        std::fs::write(dir.join(old), b"o").unwrap();
        age_file(&dir.join(young), 23);
        age_file(&dir.join(old), 25);
        assert_eq!(
            set_aside_orphan_sidecars(&dir, ORPHAN_SIDECAR_MIN_AGE).len(),
            1
        );
        assert!(dir.join(young).exists());
        assert!(!dir.join(old).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn plant_old_orphans(dir: &Path) -> [&'static str; 2] {
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let names = [
            "rules-2024-01-01.1-2.jsonl.manifest.json",
            "events-2024-01-01.1-2.jsonl.manifest.json",
        ];
        for n in names {
            std::fs::write(ad.join(n), b"orphan").unwrap();
            age_file(&ad.join(n), 25);
        }
        names
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn an_archiving_sweep_sets_old_orphan_sidecars_aside(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        let dir = temp_dir();
        let names = plant_old_orphans(&dir).await;
        let ad = dir.join("audit_archive");
        run_prune(&pool, &dir, 5, true, None).await.unwrap();
        for n in names {
            assert!(!ad.join(n).exists(), "{n} should be set aside (rules)");
        }
        // The rules sweep only tidies; run the events sweep for its own call.
        let ad_names = entries(&ad);
        assert!(
            ad_names.iter().all(|n| n.contains(".orphan-")),
            "{ad_names:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        let dir = temp_dir();
        let names = plant_old_orphans(&dir).await;
        let ad = dir.join("audit_archive");
        run_prune_events(&pool, &dir, 5, true, None).await.unwrap();
        assert!(entries(&ad)
            .iter()
            .any(|n| n.starts_with(names[1]) && n.contains(".orphan-")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_non_archiving_sweep_leaves_orphan_sidecars_alone(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        let dir = temp_dir();
        let names = plant_old_orphans(&dir).await;
        let ad = dir.join("audit_archive");
        run_prune(&pool, &dir, 5, false, None).await.unwrap();
        run_prune_events(&pool, &dir, 5, false, None).await.unwrap();
        for n in names {
            assert!(ad.join(n).exists());
        }
        assert_eq!(entries(&ad).len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_move_aside_is_reported_and_leaves_the_file() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let name = "rules-2024-01-01.1-2.jsonl.manifest.json";
        std::fs::write(dir.join(name), b"orphan").unwrap();
        FAIL_MOVE_ASIDE.lock().unwrap().push(dir.clone());
        let moves = set_aside_orphan_sidecars(&dir, Duration::ZERO);
        FAIL_MOVE_ASIDE.lock().unwrap().retain(|p| p != &dir);
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].from, name);
        assert_eq!(moves[0].to, None);
        assert_eq!(moves[0].reason, "orphan");
        assert!(moves[0]
            .error
            .as_deref()
            .unwrap()
            .contains("injected move failure"));
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"orphan");
        assert_eq!(entries(&dir), [name]);
        let notes = SweepNotes {
            set_aside: moves,
            unsynced_publishes: 0,
        };
        assert_eq!((notes.moved(), notes.failed_moves()), (0, 1));
        assert!(notes_suffix(&notes).contains("archive moves FAILED: 1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rejected_segment_is_noted_with_old_and_new_names() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        // A segment without a sidecar is a definite verification failure.
        std::fs::write(ad.join("rules-2024-01-01.5-5.jsonl"), "{\"id\":5}\n").unwrap();
        let mut ctx = SweepCtx::default();
        archive_blocking(
            &dir,
            STREAM_RULES,
            vec![line(5, "2024-01-01")],
            None,
            &mut ctx,
        )
        .unwrap();
        let notes = &ctx.io.notes;
        assert_eq!(notes.moved(), 1);
        assert_eq!(notes.failed_moves(), 0);
        let note = &notes.set_aside[0];
        assert_eq!(note.from, "rules-2024-01-01.5-5.jsonl");
        assert_eq!(note.reason, "rejected");
        let to = note.to.as_deref().unwrap();
        assert!(
            to.starts_with("rules-2024-01-01.5-5.jsonl.rejected-"),
            "{to}"
        );
        assert!(ad.join(to).exists());
        assert!(notes_suffix(notes).contains("archive files set aside: 1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_scheduler_suffix_is_empty_without_notes() {
        assert_eq!(notes_suffix(&SweepNotes::default()), "");
        let degraded = SweepNotes {
            set_aside: Vec::new(),
            unsynced_publishes: 2,
        };
        let msg = notes_suffix(&degraded);
        assert!(msg.contains("DEGRADED durability: 2"), "{msg}");
        assert!(msg.contains(ALLOW_UNSYNCED_DIR_ENV), "{msg}");
    }

    async fn archive_events(pool: &PgPool, action: &str) -> Vec<(String, serde_json::Value)> {
        crate::db_audit::drain().await;
        sqlx::query_as::<_, (String, serde_json::Value)>(
            "SELECT outcome, detail FROM audit_events WHERE action = $1 ORDER BY id",
        )
        .bind(action)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn seed_one_expired_rule(pool: &PgPool) {
        seed_user(pool, "u1").await;
        sqlx::query(
            "INSERT INTO rule_audit (user_id, checklist_id, rule_id, field, occurred_at) \
             VALUES ('u1', 'c', 'a', 'status', NOW() - INTERVAL '10 days')",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn rule_audit_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[cfg(unix)]
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn an_unsupported_directory_sync_deletes_nothing_by_default(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_one_expired_rule(&pool).await;
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        arm_dir_sync_failure_kind(&ad, std::io::ErrorKind::InvalidInput);
        let (res, notes) = run_prune_noted(
            &pool,
            &dir,
            5,
            true,
            None,
            crate::db_audit::RETENTION_LOCK_WAIT,
            DirSyncPolicy::default(),
        )
        .await;
        disarm_dir_sync_failure(&ad);
        let err = res.unwrap_err();
        assert!(
            format!("{err:#}").contains(ALLOW_UNSYNCED_DIR_ENV),
            "{err:#}"
        );
        assert_eq!(rule_audit_count(&pool).await, 1);
        assert!(entries(&ad).is_empty());
        assert_eq!(notes.unsynced_publishes, 0);
        assert!(archive_events(&pool, "audit_archive.durability_degraded")
            .await
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_opt_in_flag_proceeds_and_records_degraded_durability(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_one_expired_rule(&pool).await;
        seed_expired_event(&pool, 10).await;
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        arm_dir_sync_failure_kind(&ad, std::io::ErrorKind::InvalidInput);
        let policy = DirSyncPolicy::TolerateUnsupported;
        let (rules, rule_notes) = run_prune_noted(
            &pool,
            &dir,
            5,
            true,
            None,
            crate::db_audit::RETENTION_LOCK_WAIT,
            policy,
        )
        .await;
        let (events, event_notes) =
            run_prune_events_noted(&pool, &dir, 5, true, None, policy).await;
        disarm_dir_sync_failure(&ad);
        assert_eq!(rules.unwrap(), 1);
        assert!(events.unwrap() >= 1);
        assert_eq!(rule_notes.unsynced_publishes, 2);
        assert_eq!(event_notes.unsynced_publishes, 2);
        assert_eq!(rule_audit_count(&pool).await, 0);
        let rows = archive_events(&pool, "audit_archive.durability_degraded").await;
        assert_eq!(rows.len(), 2, "{rows:?}");
        let sweeps: Vec<&str> = rows
            .iter()
            .map(|(o, d)| {
                assert_eq!(o, "partial");
                assert_eq!(d["reason"], "dir_fsync_unsupported");
                assert_eq!(d["env_flag"], ALLOW_UNSYNCED_DIR_ENV);
                assert_eq!(d["unsynced_publishes"], 2);
                assert_eq!(d["sweep_ok"], true);
                d["sweep"].as_str().unwrap()
            })
            .collect();
        assert!(
            sweeps.contains(&"rules") && sweeps.contains(&"events"),
            "{sweeps:?}"
        );
        let mut merged = rule_notes;
        merged.merge(event_notes);
        assert!(notes_suffix(&merged).contains("DEGRADED durability: 4"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_sweep_audits_orphan_sidecars_it_sets_aside(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        let dir = temp_dir();
        let names = plant_old_orphans(&dir).await;
        run_prune(&pool, &dir, 5, true, None).await.unwrap();
        let rows = archive_events(&pool, "audit_archive.file_set_aside").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        let (outcome, d) = &rows[0];
        assert_eq!(outcome, "ok");
        assert_eq!(d["sweep"], "rules");
        assert_eq!(d["failed"], 0);
        assert_eq!(d["truncated"], false);
        let files = d["files"].as_array().unwrap();
        assert_eq!(files.len(), d["moved"].as_u64().unwrap() as usize);
        assert!(files.iter().any(|f| f["from"] == names[0]
            && f["reason"] == "orphan"
            && f["outcome"] == "moved"
            && f["to"].as_str().unwrap().contains(".orphan-")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failing_archive_move_is_counted_in_the_event_and_the_scheduler_message(
        pool: PgPool,
    ) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        let dir = temp_dir();
        let names = plant_old_orphans(&dir).await;
        let ad = dir.join("audit_archive");
        FAIL_MOVE_ASIDE.lock().unwrap().push(ad.clone());
        let res = run_scheduled(&pool, &dir, 5, true, None).await;
        FAIL_MOVE_ASIDE.lock().unwrap().retain(|p| p != &ad);
        let msg = res.unwrap();
        assert!(msg.contains("archive moves FAILED: 4"), "{msg}");
        for n in names {
            assert!(ad.join(n).exists());
        }
        let rows = archive_events(&pool, "audit_archive.file_set_aside").await;
        assert_eq!(rows.len(), 2, "{rows:?}");
        for (outcome, d) in &rows {
            assert_eq!(outcome, "partial");
            assert_eq!(d["failed"], 2);
            assert_eq!(d["files"][0]["outcome"], "failed");
            assert!(d["files"][0]["error"]
                .as_str()
                .unwrap()
                .contains("injected move failure"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_clean_sweep_writes_no_archive_audit_events(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_one_expired_rule(&pool).await;
        let dir = temp_dir();
        let msg = run_scheduled(&pool, &dir, 5, true, None).await.unwrap();
        for part in ["set aside", "FAILED", "DEGRADED"] {
            assert!(!msg.contains(part), "{msg}");
        }
        assert!(msg.starts_with("pruned 1 rows and "), "{msg}");
        for action in [
            "audit_archive.file_set_aside",
            "audit_archive.durability_degraded",
        ] {
            assert!(archive_events(&pool, action).await.is_empty(), "{action}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn aside(i: usize, failed: bool) -> SetAside {
        SetAside {
            from: format!("f{i}"),
            to: (!failed).then(|| format!("t{i}")),
            reason: "orphan",
            error: failed.then(|| "boom".to_string()),
        }
    }

    #[test]
    fn the_set_aside_detail_is_capped_failed_first_and_totals_count_everything() {
        let mut notes = SweepNotes::default();
        for i in 0..150 {
            notes.set_aside.push(aside(i, false));
        }
        for i in 150..155 {
            notes.set_aside.push(aside(i, true));
        }
        let d = set_aside_detail("rules", &notes, crate::db_audit::MAX_REJECTED_LISTED);
        assert_eq!(d["truncated"], true);
        assert_eq!(d["moved"], 150);
        assert_eq!(d["failed"], 5);
        let files = d["files"].as_array().unwrap();
        assert_eq!(files.len(), crate::db_audit::MAX_REJECTED_LISTED);
        assert!(files[..5]
            .iter()
            .all(|f| f["outcome"] == "failed" && f["error"] == "boom"));
        assert!(files[5..]
            .iter()
            .all(|f| f["outcome"] == "moved" && f.get("error").is_none()));
        let all = set_aside_detail("events", &notes, 1000);
        assert_eq!(all["truncated"], false);
        assert_eq!(all["files"].as_array().unwrap().len(), 155);
    }

    #[test]
    fn a_long_error_is_truncated_on_a_char_boundary() {
        let long = "\u{e9}".repeat(MAX_SET_ASIDE_ERROR_CHARS * 2);
        let out = bounded_error(&std::io::Error::other(long));
        assert_eq!(out.chars().count(), MAX_SET_ASIDE_ERROR_CHARS);
        assert_eq!(bounded_error(&std::io::Error::other("short")), "short");
    }

    #[test]
    fn the_degraded_detail_records_sweep_ok_both_ways() {
        for ok in [true, false] {
            let d = degraded_detail("events", 3, ok);
            assert_eq!(d["sweep_ok"], ok);
            assert_eq!(d["unsynced_publishes"], 3);
            assert_eq!(d["reason"], "dir_fsync_unsupported");
        }
    }

    #[test]
    fn a_failed_tidy_task_counts_as_a_failed_move_with_its_own_reason() {
        let notes = SweepNotes {
            set_aside: vec![SetAside {
                from: "(archive tidy task)".into(),
                to: None,
                reason: "tidy_task_failed",
                error: Some("panicked".into()),
            }],
            unsynced_publishes: 0,
        };
        assert_eq!(notes.failed_moves(), 1);
        let d = set_aside_detail("rules", &notes, 10);
        assert_eq!(d["files"][0]["reason"], "tidy_task_failed");
    }

    #[test]
    fn a_failed_move_of_a_rejected_segment_is_counted_and_leaves_the_file() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let name = "rules-2024-01-01.5-5.jsonl";
        std::fs::write(dir.join(name), b"x").unwrap();
        FAIL_MOVE_ASIDE.lock().unwrap().push(dir.clone());
        let mut notes = SweepNotes::default();
        preserve_rejected(&dir, name, &mut notes);
        FAIL_MOVE_ASIDE.lock().unwrap().retain(|p| p != &dir);
        assert_eq!(notes.failed_moves(), 1);
        assert_eq!(notes.set_aside[0].reason, "rejected");
        assert_eq!(notes.set_aside[0].from, name);
        assert!(dir.join(name).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn run_scheduled_reports_degraded_durability_under_the_tolerant_policy(pool: PgPool) {
        crate::test_fixtures::set_audit_retention_floor(&pool, 0).await;
        seed_one_expired_rule(&pool).await;
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        arm_dir_sync_failure_kind(&ad, std::io::ErrorKind::InvalidInput);
        let res = run_scheduled_with(
            &pool,
            &dir,
            5,
            true,
            None,
            DirSyncPolicy::TolerateUnsupported,
        )
        .await;
        disarm_dir_sync_failure(&ad);
        let msg = res.unwrap();
        assert!(msg.contains("DEGRADED durability"), "{msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
