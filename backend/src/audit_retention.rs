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
//! Segments are written to a temp file, fsynced and renamed; a failed write
//! leaves no partial segment. Archiving is idempotent by row id: ids already
//! present in that date's verified segments are skipped, so a
//! retry after a failed delete never duplicates a row.
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

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::Path;

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

/// `(first, last)` from `<stream>-<date>.<first>-<last>.jsonl`, if `name` is a
/// segment of `stream` on `date`.
fn segment_range(name: &str, stream: &str, date: &str) -> Option<(i64, i64)> {
    let rest = name
        .strip_prefix(&format!("{stream}-{date}."))?
        .strip_suffix(".jsonl")?;
    let (a, b) = rest.split_once('-')?;
    let digits = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    if !digits(a) || !digits(b) {
        return None;
    }
    Some((a.parse().ok()?, b.parse().ok()?))
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

/// Move a rejected segment (and its sidecar) aside as
/// `<name>.rejected-<UTC timestamp>` so it is kept as evidence and never
/// counted again.
fn preserve_rejected(dir: &Path, name: &str) {
    let ts = Utc::now().format("%Y%m%dT%H%M%S%.3fZ").to_string();
    for file in [name.to_string(), format!("{name}.manifest.json")] {
        let from = dir.join(&file);
        if !from.exists() {
            continue;
        }
        let mut to = dir.join(format!("{file}.rejected-{ts}"));
        if to.exists() {
            to = dir.join(format!("{file}.rejected-{ts}-{}", uuid::Uuid::new_v4().simple()));
        }
        match std::fs::rename(&from, &to) {
            Ok(()) => tracing::warn!(target: "audit", from = ?file, to = ?to.file_name(), "audit archive file preserved as rejected"),
            Err(e) => tracing::error!(target: "audit", file = ?file, "could not preserve rejected audit archive file: {e:#}"),
        }
    }
}

/// What the verified segments of `stream` on `date` hold: id -> SHA-512 of the
/// exact line. Only a segment that VERIFIES contributes (sidecar present;
/// digest, row count and id range correct; a verified signature when a key is
/// configured). A segment that fails is logged, preserved as
/// `*.rejected-<time>` and ignored. Legacy append-mode files are never read.
///
/// The caller skips a row only when its id maps to the identical line, so a
/// planted segment with a consistent digest cannot hide a real row, with or
/// without a signing key.
fn archived_lines(
    dir: &Path,
    stream: &str,
    date: &str,
    key: Option<&SigningState>,
) -> Result<HashMap<i64, String>> {
    let mut seen = HashMap::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if segment_range(&name, stream, date).is_none() {
            continue;
        }
        let verified = verify_segment(dir, &name, key).and_then(|v| {
            if key.is_some() && v.status != SignatureStatus::Verified {
                anyhow::bail!("signature status is {}", v.status.as_str());
            }
            lines_in(&v.body)
        });
        match verified {
            Ok(lines) => seen.extend(lines),
            Err(e) => {
                tracing::warn!(
                    target: "audit",
                    segment = ?name,
                    "audit archive segment failed verification, its rows will be archived again: {e:#}"
                );
                preserve_rejected(dir, &name);
            }
        }
    }
    Ok(seen)
}

/// Temp file, fsync, rename, fsync the directory.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, dir.join(name))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.with_context(|| format!("write {name}"))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn write_segment(
    dir: &Path,
    stream: &str,
    date: &str,
    group: &[&ArchiveLine],
    key: Option<&SigningState>,
) -> Result<()> {
    let (Some(first), Some(last)) = (group.first(), group.last()) else {
        return Ok(());
    };
    let mut body = Vec::new();
    for l in group {
        body.extend_from_slice(l.line.as_bytes());
        body.push(b'\n');
    }
    let name = format!("{stream}-{date}.{}-{}.jsonl", first.id, last.id);
    // A file of this name that was not accepted (or holds other lines) is kept.
    if dir.join(&name).exists() {
        preserve_rejected(dir, &name);
    }
    write_atomic(dir, &name, &body)?;
    let manifest = SegmentManifest {
        kind: integrity::ARCHIVE_TYPE.into(),
        version: 1,
        stream: stream.into(),
        file: name.clone(),
        rows: group.len() as u64,
        first_id: first.id,
        last_id: last.id,
        digest: Digest { algorithm: "sha-512".into(), value: integrity::sha512_hex(&body) },
        signers: integrity::signers_for(key),
    };
    let payload = serde_json::to_vec(&manifest)?;
    let envelope = integrity::seal(
        integrity::ARCHIVE_DOMAIN,
        integrity::ARCHIVE_TYPE,
        &payload,
        key,
    );
    write_atomic(
        dir,
        &format!("{name}.manifest.json"),
        &serde_json::to_vec_pretty(&envelope)?,
    )
}

/// Verified archived lines (id -> line digest) per UTC date, for one sweep.
type SeenCache = HashMap<String, HashMap<i64, String>>;

fn archive_blocking(
    data_dir: &Path,
    stream: &str,
    rows: Vec<ArchiveLine>,
    key: Option<&SigningState>,
    cache: &mut SeenCache,
) -> Result<()> {
    let dir = data_dir.join("audit_archive");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create archive dir {}", dir.display()))?;
    // Group by UTC date; `occurred_at` can be out of order versus id.
    let mut by_date: BTreeMap<String, Vec<&ArchiveLine>> = BTreeMap::new();
    for row in &rows {
        by_date.entry(row.occurred_at.format("%Y-%m-%d").to_string()).or_default().push(row);
    }
    for (date, mut group) in by_date {
        if !cache.contains_key(&date) {
            cache.insert(date.clone(), archived_lines(&dir, stream, &date, key)?);
        }
        let seen = cache.entry(date.clone()).or_default();
        // Skip a row only when a verified segment holds this exact line.
        group.retain(|l| seen.get(&l.id) != Some(&integrity::sha512_hex(l.line.as_bytes())));
        group.sort_by_key(|l| l.id);
        group.dedup_by_key(|l| l.id);
        write_segment(&dir, stream, &date, &group, key)?;
        seen.extend(group.iter().map(|l| (l.id, integrity::sha512_hex(l.line.as_bytes()))));
    }
    Ok(())
}

async fn archive_rows(
    data_dir: &Path,
    stream: &'static str,
    rows: Vec<ArchiveLine>,
    key: Option<&SigningState>,
    cache: &mut SeenCache,
) -> Result<()> {
    let data_dir = data_dir.to_path_buf();
    let key = key.cloned();
    let mut local = std::mem::take(cache);
    let (res, local) = tokio::task::spawn_blocking(move || {
        let r = archive_blocking(&data_dir, stream, rows, key.as_ref(), &mut local);
        (r, local)
    })
    .await
    .context("archive task")?;
    *cache = local;
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
) -> Result<VerifiedSegment> {
    let body = std::fs::read(dir.join(segment))?;
    let sidecar = std::fs::read(dir.join(format!("{segment}.manifest.json")))?;
    let v = integrity::verify_envelope(
        integrity::ARCHIVE_DOMAIN,
        integrity::ARCHIVE_TYPE,
        &sidecar,
        None,
        key,
    )?;
    let m: SegmentManifest = serde_json::from_slice(&v.payload)?;
    anyhow::ensure!(m.file == segment, "manifest is for another file");
    anyhow::ensure!(m.digest.algorithm == "sha-512", "unsupported digest algorithm");
    anyhow::ensure!(m.digest.value == integrity::sha512_hex(&body), "segment digest mismatch");
    let ids: Vec<i64> = lines_in(&body)?.into_iter().map(|(i, _)| i).collect();
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
    Ok(VerifiedSegment { status: v.status, body })
}

/// Range from a segment file name of any stream and date.
fn segment_range_any(name: &str) -> Option<(i64, i64)> {
    let rest = name.strip_suffix(".jsonl")?;
    let (_, range) = rest.rsplit_once('.')?;
    let (a, b) = range.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
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
pub async fn run_prune(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    signing: Option<&SigningState>,
) -> Result<usize> {
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
        archive_rows(data_dir, STREAM_RULES, lines, signing, &mut SeenCache::new())
            .await
            .context("write audit archive segment")?;
    }

    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    let mut tx = pool.begin().await.context("begin rule_audit prune tx")?;
    crate::db_audit::set_maintenance(&mut tx, "retention").await.context("set audit maintenance mode")?;
    let deleted = sqlx::query("DELETE FROM rule_audit WHERE id = ANY($1::bigint[])")
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .context("delete pruned rule_audit rows")?
        .rows_affected();
    tx.commit().await.context("commit rule_audit prune")?;

    Ok(deleted as usize)
}

/// One `audit_events` row, shaped for JSONL archival (raw columns).
#[derive(Debug, Serialize, sqlx::FromRow)]
struct EventRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    user_id: String,
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
    run_prune_events_batched(pool, data_dir, retain_days, archive, EVENT_PRUNE_BATCH, signing).await
}

async fn run_prune_events_batched(
    pool: &PgPool,
    data_dir: &Path,
    retain_days: i64,
    archive: bool,
    batch: i64,
    signing: Option<&SigningState>,
) -> Result<usize> {
    let mut total = 0usize;
    let mut cache = SeenCache::new();
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
            archive_rows(data_dir, STREAM_EVENTS, lines, signing, &mut cache)
                .await
                .context("write audit events archive segment")?;
        }

        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        let mut tx = pool.begin().await.context("begin audit_events prune tx")?;
        crate::db_audit::set_maintenance(&mut tx, "retention").await.context("set audit maintenance mode")?;
        let deleted = sqlx::query("DELETE FROM audit_events WHERE id = ANY($1::bigint[])")
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .context("delete pruned audit_events rows")?
            .rows_affected() as usize;
        tx.commit().await.context("commit audit_events prune")?;
        total += deleted;
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
    let rules = run_prune(pool, data_dir, retain_days, archive, signing).await;
    let events = run_prune_events(pool, data_dir, retain_days, archive, signing).await;
    match (rules, events) {
        (Ok(n), Ok(e)) => Ok(format!(
            "pruned {n} rows and {e} events (retain_days={retain_days}, archive={archive})"
        )),
        (r, e) => {
            let show = |x: Result<usize>| match x {
                Ok(n) => format!("pruned {n}"),
                Err(err) => format!("failed: {err:#}"),
            };
            anyhow::bail!("audit retention: rule_audit {}; audit_events {}", show(r), show(e))
        }
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
    Ok(ArchiveLine { id: row.id, occurred_at: row.occurred_at, line })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrity::test_key;
    use crate::test_fixtures::seed_user;

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_rule_audit_deletes_and_archives_under_the_guard(pool: PgPool) {
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
        let left: Vec<String> = sqlx::query_scalar("SELECT rule_id FROM rule_audit").fetch_all(&pool).await.unwrap();
        assert_eq!(left, ["new"]);
        assert!(dir.join("audit_archive").exists());
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn prune_events_keys_on_the_last_repeat_and_archives_the_counter(pool: PgPool) {
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
        let n = run_prune_events(&pool, &dir, 365, true, None).await.unwrap();
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
        assert_eq!(run_prune_events(&pool, &dir2, 5, false, None).await.unwrap(), 1);
        assert!(!dir2.exists());
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
        seed_user(&pool, "u1").await;
        for _ in 0..5 {
            seed_expired_event(&pool, 400).await;
        }
        seed_expired_event(&pool, 1).await;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let n = run_prune_events_batched(&pool, &dir, 365, true, 2, None).await.unwrap();
        assert_eq!(n, 5);
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!(left, 1);
        let mut lines = 0;
        for seg in segments(&dir) {
            lines += std::fs::read_to_string(dir.join("audit_archive").join(seg)).unwrap().lines().count();
        }
        assert_eq!(lines, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn scheduled_run_prunes_expired_events_and_reports_them(pool: PgPool) {
        seed_user(&pool, "u1").await;
        seed_expired_event(&pool, 400).await;
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let msg = run_scheduled(&pool, &dir, 365, false, None).await.unwrap();
        assert!(msg.contains("1 events"), "{msg}");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
        assert_eq!(left, 0);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failing_rule_audit_prune_does_not_skip_the_event_prune(pool: PgPool) {
        seed_user(&pool, "u1").await;
        seed_expired_event(&pool, 400).await;
        sqlx::query("DROP TABLE rule_audit").execute(&pool).await.unwrap();
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let err = run_scheduled(&pool, &dir, 365, false, None).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("rule_audit failed") && msg.contains("audit_events pruned 1"), "{msg}");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events").fetch_one(&pool).await.unwrap();
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
        archive_blocking(&dir, STREAM_RULES, vec![line(3, "2024-01-01"), line(1, "2024-01-01")], Some(&k), &mut SeenCache::new()).unwrap();
        let ad = dir.join("audit_archive");
        assert_eq!(segments(&dir), ["rules-2024-01-01.1-3.jsonl"]);
        let seg = "rules-2024-01-01.1-3.jsonl";
        assert_eq!(verify_segment(&ad, seg, Some(&k)).unwrap().status, SignatureStatus::Verified);
        // Flip a byte in the segment.
        let orig = std::fs::read(ad.join(seg)).unwrap();
        let mut bad = orig.clone();
        bad[2] ^= 1;
        std::fs::write(ad.join(seg), &bad).unwrap();
        assert!(verify_segment(&ad, seg, Some(&k)).is_err());
        std::fs::write(ad.join(seg), &orig).unwrap();
        // Rewrite the manifest's digest: the signature no longer covers it.
        let mp = ad.join(format!("{seg}.manifest.json"));
        let mut env: integrity::Envelope = serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
        let mut payload = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &env.payload).unwrap();
        let i = payload.iter().position(|&b| b == b'3').unwrap();
        payload[i] = b'4';
        env.payload = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &payload);
        std::fs::write(&mp, serde_json::to_vec(&env).unwrap()).unwrap();
        assert!(verify_segment(&ad, seg, Some(&k)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn without_a_key_the_manifest_carries_a_digest_only() {
        let dir = temp_dir();
        archive_blocking(&dir, STREAM_EVENTS, vec![line(5, "2024-02-02")], None, &mut SeenCache::new()).unwrap();
        let ad = dir.join("audit_archive");
        let seg = "events-2024-02-02.5-5.jsonl";
        assert_eq!(verify_segment(&ad, seg, None).unwrap().status, SignatureStatus::Unsigned);
        let sidecar: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ad.join(format!("{seg}.manifest.json"))).unwrap()).unwrap();
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
        let rows = || vec![line(1, "2024-01-01"), line(2, "2024-01-01"), line(9, "2024-01-02")];
        archive_blocking(&dir, STREAM_RULES, rows(), Some(&k), &mut SeenCache::new()).unwrap();
        let before = std::fs::read_dir(dir.join("audit_archive")).unwrap().count();
        archive_blocking(&dir, STREAM_RULES, rows(), Some(&k), &mut SeenCache::new()).unwrap();
        assert_eq!(std::fs::read_dir(dir.join("audit_archive")).unwrap().count(), before);
        // A partial overlap writes only the new id, as its own segment.
        archive_blocking(&dir, STREAM_RULES, vec![line(2, "2024-01-01"), line(7, "2024-01-01")], Some(&k), &mut SeenCache::new()).unwrap();
        assert_eq!(
            segments(&dir),
            ["rules-2024-01-01.1-2.jsonl", "rules-2024-01-01.7-7.jsonl", "rules-2024-01-02.9-9.jsonl"]
        );
        // No temp files linger.
        assert!(std::fs::read_dir(dir.join("audit_archive")).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_append_files_are_left_alone_and_never_trusted_to_skip_a_row() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        let legacy = "{\"id\":1,\"v\":\"old\"}\n{\"id\":2,\"v\":\"old\"}\n";
        std::fs::write(ad.join("2024-01-01.jsonl"), legacy).unwrap();
        archive_blocking(&dir, STREAM_RULES, vec![line(2, "2024-01-01"), line(3, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        assert_eq!(std::fs::read_to_string(ad.join("2024-01-01.jsonl")).unwrap(), legacy);
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
        archive_blocking(&dir, STREAM_RULES, vec![line(5, "2024-01-01")], Some(&k), &mut SeenCache::new()).unwrap();
        let seg = "rules-2024-01-01.5-5.jsonl";
        assert_eq!(verify_segment(&ad, seg, Some(&k)).unwrap().status, SignatureStatus::Verified);
        // A planted segment with a forged, digest-only sidecar is rejected too when a key is set.
        let forged = temp_dir();
        archive_blocking(&forged, STREAM_RULES, vec![line(6, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        for f in ["rules-2024-01-01.6-6.jsonl", "rules-2024-01-01.6-6.jsonl.manifest.json"] {
            std::fs::copy(forged.join("audit_archive").join(f), ad.join(f)).unwrap();
        }
        archive_blocking(&dir, STREAM_RULES, vec![line(6, "2024-01-01")], Some(&k), &mut SeenCache::new()).unwrap();
        // The unsigned segment was replaced (same name) by a signed one.
        assert_eq!(verify_segment(&ad, "rules-2024-01-01.6-6.jsonl", Some(&k)).unwrap().status, SignatureStatus::Verified);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&forged);
    }

    #[test]
    fn a_segment_missing_its_sidecar_or_tampered_is_archived_again() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        archive_blocking(&dir, STREAM_RULES, vec![line(1, "2024-01-01"), line(2, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        let seg = "rules-2024-01-01.1-2.jsonl";
        let side = ad.join(format!("{seg}.manifest.json"));
        // No sidecar: rewritten (same name, replaced) with a sidecar.
        std::fs::remove_file(&side).unwrap();
        archive_blocking(&dir, STREAM_RULES, vec![line(1, "2024-01-01"), line(2, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        assert!(verify_segment(&ad, seg, None).is_ok());
        assert_eq!(rejected(&dir).len(), 1, "the sidecar-less segment is preserved");
        // Tampered (drops id 2, keeps a valid line shape): re-archived from the rows.
        std::fs::write(ad.join(seg), "{\"id\":1,\"v\":\"x\"}\n{\"id\":2,\"v\":\"evil\"}\n").unwrap();
        assert!(verify_segment(&ad, seg, None).is_err());
        archive_blocking(&dir, STREAM_RULES, vec![line(1, "2024-01-01"), line(2, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        assert!(verify_segment(&ad, seg, None).is_ok());
        assert!(!std::fs::read_to_string(ad.join(seg)).unwrap().contains("evil"));
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

    fn forged_line(id: i64, date: &str) -> ArchiveLine {
        ArchiveLine { line: format!("{{\"id\":{id},\"v\":\"FORGED\"}}"), ..line(id, date) }
    }

    #[test]
    fn a_planted_self_consistent_segment_cannot_hide_a_real_row() {
        // No signing key: a forged line with a matching digest sidecar.
        let (dir, forged) = (temp_dir(), temp_dir());
        archive_blocking(&forged, STREAM_RULES, vec![forged_line(5, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        plant(&forged, &dir);
        archive_blocking(&dir, STREAM_RULES, vec![line(5, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        let ad = dir.join("audit_archive");
        let seg = "rules-2024-01-01.5-5.jsonl";
        let v = verify_segment(&ad, seg, None).unwrap();
        assert!(String::from_utf8(v.body).unwrap().contains("\"x\"") );
        // The forged file is kept as evidence, with its sidecar.
        let kept = rejected(&dir);
        assert_eq!(kept.len(), 2, "{kept:?}");
        let seg_kept = kept.iter().find(|n| !n.contains(".manifest.json")).unwrap();
        assert!(std::fs::read_to_string(ad.join(seg_kept)).unwrap().contains("FORGED"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&forged);
    }

    #[test]
    fn a_planted_segment_holding_the_genuine_line_is_skipped() {
        let (dir, genuine) = (temp_dir(), temp_dir());
        archive_blocking(&genuine, STREAM_RULES, vec![line(5, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        plant(&genuine, &dir);
        archive_blocking(&dir, STREAM_RULES, vec![line(5, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        assert_eq!(segments(&dir), ["rules-2024-01-01.5-5.jsonl"]);
        assert!(rejected(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&genuine);
    }

    #[test]
    fn an_unknown_key_segment_is_rearchived_with_a_key_and_matched_by_line_without_one() {
        let (a, b) = (test_key(1), test_key(2));
        let (dir, other) = (temp_dir(), temp_dir());
        archive_blocking(&other, STREAM_RULES, vec![line(5, "2024-01-01")], Some(&a), &mut SeenCache::new()).unwrap();
        plant(&other, &dir);
        // No key here: signed by another key, so it cannot be checked, but the line matches.
        archive_blocking(&dir, STREAM_RULES, vec![line(5, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        assert!(rejected(&dir).is_empty());
        // No key, different line: archived.
        archive_blocking(&dir, STREAM_RULES, vec![forged_line(5, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        assert_eq!(rejected(&dir).len(), 2);
        // With key B the key-A segment is unknown_key: rejected and rewritten, verified.
        let (dir2, other2) = (temp_dir(), temp_dir());
        archive_blocking(&other2, STREAM_RULES, vec![line(5, "2024-01-01")], Some(&a), &mut SeenCache::new()).unwrap();
        plant(&other2, &dir2);
        archive_blocking(&dir2, STREAM_RULES, vec![line(5, "2024-01-01")], Some(&b), &mut SeenCache::new()).unwrap();
        assert_eq!(rejected(&dir2).len(), 2);
        assert_eq!(
            verify_segment(&dir2.join("audit_archive"), "rules-2024-01-01.5-5.jsonl", Some(&b)).unwrap().status,
            SignatureStatus::Verified
        );
        for d in [dir, other, dir2, other2] {
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn rejected_files_are_never_counted_as_archived() {
        let dir = temp_dir();
        let ad = dir.join("audit_archive");
        std::fs::create_dir_all(&ad).unwrap();
        std::fs::write(ad.join("rules-2024-01-01.5-5.jsonl.rejected-20240101T000000.000Z"), "{\"id\":5}\n").unwrap();
        archive_blocking(&dir, STREAM_RULES, vec![line(5, "2024-01-01")], None, &mut SeenCache::new()).unwrap();
        assert_eq!(segments(&dir), ["rules-2024-01-01.5-5.jsonl"]);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_delete_followed_by_a_retry_archives_each_id_once(pool: PgPool) {
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
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM rule_audit ORDER BY id").fetch_all(&pool).await.unwrap();
        let dir = temp_dir();
        assert_eq!(run_prune(&pool, &dir, 5, true, Some(&k)).await.unwrap(), 2);
        // Put the rows back under their ids: as if the delete had failed after the archive was written.
        for (id, rule) in ids.iter().zip(["a", "b"]) {
            sqlx::query(
                "INSERT INTO rule_audit (id, user_id, checklist_id, rule_id, field, occurred_at) \
                 VALUES ($1, 'u1', 'c', $2, 'status', NOW() - INTERVAL '10 days')",
            )
            .bind(id)
            .bind(rule)
            .execute(&pool)
            .await
            .unwrap();
        }
        assert_eq!(run_prune(&pool, &dir, 5, true, Some(&k)).await.unwrap(), 2);
        let mut seen = Vec::new();
        for seg in segments(&dir) {
            assert_eq!(
                verify_segment(&dir.join("audit_archive"), &seg, Some(&k)).unwrap().status,
                SignatureStatus::Verified
            );
            seen.extend(lines_in(&std::fs::read(dir.join("audit_archive").join(&seg)).unwrap()).unwrap().into_iter().map(|(i, _)| i));
        }
        seen.sort();
        assert_eq!(seen, ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_failed_archive_write_deletes_nothing(pool: PgPool) {
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
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_audit").fetch_one(&pool).await.unwrap();
        assert_eq!(left, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
