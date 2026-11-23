//! Stage, commit, publish for catalog JSON files.
//!
//! A catalog file is first written to `stigs/.upload-{id}.{uuid}.tmp` (same
//! directory, so the later rename is atomic), the catalog row and audit row are
//! committed in one transaction, and only then is the temp renamed to
//! `{id}.json`. Readers open `{id}.json` by exact name, so they never see a
//! half-written file, and the file never gets ahead of the catalog row.
//!
//! A crash after the commit but before the rename leaves the temp holding the
//! new content; [`sweep_stale`] rolls it forward (or deletes it when the
//! catalog row does not match).

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::PgPool;
use tokio::io::AsyncWriteExt;

/// A temp file older than this is no longer an in-flight upload.
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

/// Largest temp file the sweep reads.
const MAX_SWEEP_BYTES: u64 = 64 * 1024 * 1024;

/// Most temp files one sweep looks at.
const MAX_SWEEP_FILES: usize = 1000;

static PUBLISH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Held across commit and rename so two uploads of one id cannot commit in one
/// order and rename in the other. Per process.
pub(crate) async fn publish_lock() -> tokio::sync::MutexGuard<'static, ()> {
    PUBLISH_LOCK.lock().await
}

/// A staged catalog file. No `Drop`: a temp left after a commit must survive
/// so the sweep can roll it forward.
pub(crate) struct Staged {
    tmp: PathBuf,
    pub(crate) dest: PathBuf,
}

/// Write `json` to a fresh temp file next to its destination and sync it.
pub(crate) async fn stage(stigs_dir: &Path, id: &str, json: &str) -> io::Result<Staged> {
    let tmp = stigs_dir.join(format!(
        ".upload-{id}.{}.tmp",
        crate::crypto::rand::uuid_v4()
    ));
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .await?;
    let written = async {
        f.write_all(json.as_bytes()).await?;
        f.sync_all().await
    }
    .await;
    drop(f);
    if let Err(e) = written {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    Ok(Staged {
        tmp,
        dest: stigs_dir.join(format!("{id}.json")),
    })
}

impl Staged {
    /// Rename the temp into place.
    pub(crate) async fn publish(&self) -> io::Result<()> {
        tokio::fs::rename(&self.tmp, &self.dest).await
    }

    /// Remove the temp; an already-missing file is fine.
    pub(crate) async fn discard(&self) {
        if let Err(e) = tokio::fs::remove_file(&self.tmp).await {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::warn!("could not remove staged catalog file: {e}");
            }
        }
    }
}

/// The id and uuid of a `.upload-{id}.{uuid}.tmp` name, if it is one.
fn parse_tmp_name(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(".upload-")?.strip_suffix(".tmp")?;
    let (id, uuid) = rest.rsplit_once('.')?;
    if !crate::stig_id::is_valid_new(id) || uuid::Uuid::parse_str(uuid).is_err() {
        return None;
    }
    Some(id)
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Meta {
    #[serde(default)]
    title: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    release_info: String,
    #[serde(default)]
    rules: Vec<serde::de::IgnoredAny>,
}

struct Candidate {
    path: PathBuf,
    id: String,
    mtime: std::time::SystemTime,
    meta: Option<Meta>,
}

/// Temps that match the name pattern and the age gate; only those are opened.
/// The 1000 cap counts candidates, not every directory entry looked at.
fn scan(stigs_dir: &Path, older_than: Duration) -> Vec<Candidate> {
    let Ok(rd) = std::fs::read_dir(stigs_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in rd.flatten() {
        if out.len() >= MAX_SWEEP_FILES {
            break;
        }
        let name = ent.file_name();
        let Some(id) = name.to_str().and_then(parse_tmp_name) else {
            continue;
        };
        let path = ent.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !md.is_file() {
            continue;
        }
        let Ok(mtime) = md.modified() else {
            continue;
        };
        if !mtime.elapsed().is_ok_and(|age| age >= older_than) {
            continue;
        }
        let meta = if md.len() <= MAX_SWEEP_BYTES {
            std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
        } else {
            None
        };
        out.push(Candidate {
            path,
            id: id.to_string(),
            mtime,
            meta,
        });
    }
    out
}

/// What the sweep did with one temp.
enum Swept {
    RolledForward,
    Deleted(&'static str),
    Skipped,
}

async fn sweep_one(stigs_dir: &Path, pool: &PgPool, c: &Candidate) -> Swept {
    // Held across the lookup and the rename/delete so a concurrent upload of
    // this id cannot commit or rename in between.
    let _guard = publish_lock().await;
    let dest = stigs_dir.join(format!("{}.json", c.id));
    let newer_published = tokio::fs::metadata(&dest)
        .await
        .and_then(|m| m.modified())
        .is_ok_and(|m| m >= c.mtime);
    let mut reason = "no_matching_row";
    let mut matches = false;
    if newer_published {
        reason = "newer_published_file";
    } else if let Some(m) = &c.meta {
        let row: Result<Option<(String, String, String, i32)>, _> = sqlx::query_as(
            "SELECT title, version, release_info, rule_count FROM stigs_catalog WHERE id = $1",
        )
        .bind(&c.id)
        .fetch_optional(pool)
        .await;
        match row {
            Ok(Some((title, version, release_info, rule_count))) => {
                let want_title = if m.title.is_empty() { &c.id } else { &m.title };
                matches = title == *want_title
                    && version == m.version
                    && release_info == m.release_info
                    && i64::from(rule_count) == m.rules.len() as i64;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("catalog temp sweep lookup failed: {e}");
                return Swept::Skipped;
            }
        }
    }
    if matches {
        match tokio::fs::rename(&c.path, &dest).await {
            Ok(()) => Swept::RolledForward,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Swept::Skipped,
            Err(e) => {
                tracing::warn!(target: "audit", stig_id = %c.id, "roll-forward failed: {e}");
                Swept::Skipped
            }
        }
    } else {
        match tokio::fs::remove_file(&c.path).await {
            Ok(()) => Swept::Deleted(reason),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Swept::Skipped,
            Err(e) => {
                tracing::warn!(target: "audit", stig_id = %c.id, "temp delete failed: {e}");
                Swept::Skipped
            }
        }
    }
}

/// Roll forward or delete temps older than `older_than`, recording each action
/// as a system audit event. Errors are logged and never fail the caller.
pub(crate) async fn sweep_stale(stigs_dir: &Path, pool: &PgPool, older_than: Duration) {
    let dir = stigs_dir.to_path_buf();
    let found = match tokio::task::spawn_blocking(move || scan(&dir, older_than)).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("catalog temp sweep task failed: {e}");
            return;
        }
    };
    for c in found {
        let (action, reason) = match sweep_one(stigs_dir, pool, &c).await {
            Swept::RolledForward => {
                tracing::warn!(target: "audit", stig_id = %c.id,
                    "rolled forward a catalog file left by an interrupted upload");
                ("catalog.file_rolled_forward", "interrupted_upload")
            }
            Swept::Deleted(reason) => {
                tracing::warn!(target: "audit", stig_id = %c.id,
                    reason, "deleted an orphaned catalog temp file");
                ("catalog.temp_deleted", reason)
            }
            Swept::Skipped => continue,
        };
        crate::db_audit::record_system_or_log(
            pool,
            crate::db_audit::NewSystemEvent {
                action,
                outcome: "ok",
                stig_id: Some(&c.id),
                detail: serde_json::json!({ "reason": reason }),
            },
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(crate::crypto::rand::uuid_v4().to_string());
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(d: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    const BODY: &str =
        r#"{"title":"T","description":"","version":"1","releaseInfo":"r","rules":[{}]}"#;

    #[test]
    fn tmp_names_are_parsed_strictly() {
        let u = crate::crypto::rand::uuid_v4();
        assert_eq!(
            parse_tmp_name(&format!(".upload-abc-1.{u}.tmp")),
            Some("abc-1")
        );
        assert_eq!(parse_tmp_name(&format!(".upload-ABC.{u}.tmp")), None);
        assert_eq!(parse_tmp_name(".upload-abc.nope.tmp"), None);
        assert_eq!(parse_tmp_name(".seed-x.tmp"), None);
        assert_eq!(parse_tmp_name("abc.json"), None);
    }

    #[tokio::test]
    async fn stage_leaves_the_published_file_untouched_until_publish() {
        let d = tempdir();
        std::fs::write(d.join("a.json"), "old").unwrap();
        let s = stage(&d, "a", "new").await.unwrap();
        assert_eq!(std::fs::read_to_string(d.join("a.json")).unwrap(), "old");
        assert_eq!(names(&d).len(), 2);
        s.publish().await.unwrap();
        assert_eq!(std::fs::read_to_string(d.join("a.json")).unwrap(), "new");
        assert_eq!(names(&d), ["a.json"]);
        let s = stage(&d, "a", "x").await.unwrap();
        s.discard().await;
        s.discard().await;
        assert_eq!(names(&d), ["a.json"]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn sweep_rolls_forward_a_temp_whose_catalog_row_matches(pool: PgPool) {
        let d = tempdir();
        let s = stage(&d, "swept", BODY).await.unwrap();
        sqlx::query(
            "INSERT INTO stigs_catalog (id, title, category, version, release_info, rule_count, json_path) VALUES ('swept','T','Linux','1','r',1,'x')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sweep_stale(&d, &pool, Duration::ZERO).await;
        assert_eq!(std::fs::read_to_string(&s.dest).unwrap(), BODY);
        assert_eq!(names(&d), ["swept.json"]);
        crate::db_audit::drain().await;
        let rows: Vec<(Option<String>, serde_json::Value)> = sqlx::query_as(
            "SELECT stig_id, detail FROM audit_events WHERE action = 'catalog.file_rolled_forward'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0.as_deref(), Some("swept"));
        assert_eq!(rows[0].1["reason"], "interrupted_upload");
        std::fs::remove_dir_all(&d).ok();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn sweep_does_not_overwrite_a_newer_published_file(pool: PgPool) {
        let d = tempdir();
        stage(&d, "newer", BODY).await.unwrap();
        sqlx::query(
            "INSERT INTO stigs_catalog (id, title, category, version, release_info, rule_count, json_path) VALUES ('newer','T','Linux','1','r',1,'x')",
        )
        .execute(&pool)
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        std::fs::write(d.join("newer.json"), "PUBLISHED").unwrap();
        sweep_stale(&d, &pool, Duration::ZERO).await;
        assert_eq!(
            std::fs::read_to_string(d.join("newer.json")).unwrap(),
            "PUBLISHED"
        );
        assert_eq!(names(&d), ["newer.json"]);
        crate::db_audit::drain().await;
        let reasons: Vec<String> = sqlx::query_scalar(
            "SELECT detail->>'reason' FROM audit_events WHERE action = 'catalog.temp_deleted'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(reasons, ["newer_published_file"]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn sweep_deletes_a_temp_with_no_matching_row(pool: PgPool) {
        let d = tempdir();
        stage(&d, "orphan", BODY).await.unwrap();
        stage(&d, "other", BODY).await.unwrap();
        sqlx::query(
            "INSERT INTO stigs_catalog (id, title, category, version, release_info, rule_count, json_path) VALUES ('other','DIFFERENT','Linux','1','r',1,'x')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sweep_stale(&d, &pool, Duration::ZERO).await;
        assert!(names(&d).is_empty(), "{:?}", names(&d));
        std::fs::remove_dir_all(&d).ok();
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn sweep_leaves_fresh_temps_and_foreign_names_alone(pool: PgPool) {
        let d = tempdir();
        stage(&d, "fresh", BODY).await.unwrap();
        std::fs::write(d.join(".seed-x.tmp"), "x").unwrap();
        std::fs::write(d.join("real.json"), "x").unwrap();
        let target = d.join("real.json");
        let link = d.join(format!(
            ".upload-link.{}.tmp",
            crate::crypto::rand::uuid_v4()
        ));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let before = names(&d);
        sweep_stale(&d, &pool, STALE_AFTER).await;
        assert_eq!(names(&d), before);
        // Even when old enough, a symlink is not touched.
        sweep_stale(&d, &pool, Duration::ZERO).await;
        assert!(std::fs::symlink_metadata(&link).is_ok());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
        assert!(d.join(".seed-x.tmp").exists());
        std::fs::remove_dir_all(&d).ok();
    }
}
