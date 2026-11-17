//! Dev-only seeding of the STIG data directory.
//!
//! `STIG_SEED_DIR` names a read-only directory of parsed STIG JSON (the
//! tracked `backend/data/stigs`). At start, every file there that the data
//! directory does not already hold is copied in; an existing file is never
//! overwritten, so synced or uploaded data survives restarts. Seeded files
//! that have no catalog row are indexed so a fresh database lists them.
//! Production leaves `STIG_SEED_DIR` unset and none of this runs.

use anyhow::Result;
use chrono::Utc;
use sqlx::PgPool;
use std::{collections::HashSet, io::ErrorKind, path::Path};
use tracing::{info, warn};

use crate::{
    config::StigSource,
    db::{upsert_catalog, CatalogEntry},
    parser::StigData,
};

/// The seed id for a directory entry name, if it is a `{valid id}.json` file.
fn seed_id(name: &str) -> Option<&str> {
    let id = name.strip_suffix(".json")?;
    crate::stig_id::is_valid(id).then_some(id)
}

/// Largest seed file read into memory (the biggest tracked one is ~0.7 MB).
const MAX_SEED_BYTES: u64 = 64 * 1024 * 1024;

/// Longest category accepted from a file's own JSON.
const MAX_CATEGORY_CHARS: usize = 64;

/// A JSON-supplied category, only if non-empty, bounded and printable.
fn clean_category(raw: &str) -> Option<String> {
    let t = raw.trim();
    let ok = !t.is_empty()
        && t.chars().count() <= MAX_CATEGORY_CHARS
        && t.chars().all(|c| !c.is_control());
    ok.then(|| t.to_string())
}

/// Copy one seed file crash-safely: write a temp file next to the target,
/// then hard-link it to the final name (which fails if that exists, so
/// nothing is overwritten), then drop the temp name. A crash leaves at worst
/// a stray `.seed-*.tmp`, never a truncated `{id}.json`.
/// Returns whether the file was newly placed.
fn copy_one(src: &Path, stigs_dir: &Path, name: &str) -> std::io::Result<bool> {
    let dest = stigs_dir.join(name);
    if dest.exists() {
        return Ok(false);
    }
    let tmp = stigs_dir.join(format!(".seed-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        let mut input = std::fs::File::open(src)?;
        std::io::copy(&mut input, &mut out)?;
        out.sync_all()?;
        match std::fs::hard_link(&tmp, &dest) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Copy every `{id}.json` from `seed_dir` into `stigs_dir` that is not
/// already there. Returns how many were copied. Symlinks, subdirectories
/// and names that are not valid STIG ids are ignored; a file that fails to
/// copy is logged and skipped.
pub fn copy_missing(seed_dir: &Path, stigs_dir: &Path) -> Result<usize> {
    std::fs::create_dir_all(stigs_dir)?;
    let mut copied = 0;
    for entry in std::fs::read_dir(seed_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if seed_id(name).is_none() {
            continue;
        }
        match copy_one(&entry.path(), stigs_dir, name) {
            Ok(true) => copied += 1,
            Ok(false) => {}
            Err(e) => warn!("seed: could not copy '{name}': {e}"),
        }
    }
    Ok(copied)
}

/// Insert a catalog row for each `{id}.json` in `stigs_dir` that has none.
/// Existing rows are never touched. Returns how many were added.
pub async fn index_missing(
    pool: &PgPool,
    stigs_dir: &Path,
    sources: &[StigSource],
) -> Result<usize> {
    index_missing_capped(pool, stigs_dir, sources, MAX_SEED_BYTES).await
}

async fn index_missing_capped(
    pool: &PgPool,
    stigs_dir: &Path,
    sources: &[StigSource],
    max_bytes: u64,
) -> Result<usize> {
    let existing: HashSet<String> = sqlx::query_scalar("SELECT id FROM stigs_catalog")
        .fetch_all(pool)
        .await?
        .into_iter()
        .collect();
    // Directory walking, file reads and JSON parsing are blocking work.
    let (dir, srcs) = (stigs_dir.to_path_buf(), sources.to_vec());
    let found = tokio::task::spawn_blocking(move || scan_missing(&dir, &srcs, &existing, max_bytes))
        .await??;
    let added = found.len();
    for catalog in &found {
        upsert_catalog(pool, catalog).await?;
    }
    Ok(added)
}

/// Blocking half of [`index_missing`]: the catalog entries for every
/// indexable `{id}.json` in `stigs_dir` whose id is not in `existing`.
fn scan_missing(
    stigs_dir: &Path,
    sources: &[StigSource],
    existing: &HashSet<String>,
    max_bytes: u64,
) -> Result<Vec<CatalogEntry>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(stigs_dir)? {
        let entry = entry?;
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() || entry.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue;
        }
        let name = entry.file_name();
        // New rows need the create rule (lower case); existing mixed-case
        // files stay readable but are not indexed here.
        let Some(id) = name.to_str().and_then(seed_id).filter(|i| crate::stig_id::is_valid_new(i))
        else {
            continue;
        };
        if existing.contains(id) {
            continue;
        }
        if meta.len() > max_bytes {
            warn!("seed: '{id}' is {} bytes, over the {max_bytes} cap; not indexed", meta.len());
            continue;
        }
        let bytes = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(e) => {
                warn!("seed: cannot read '{id}': {e}");
                continue;
            }
        };
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                warn!("seed: '{id}' is not valid JSON: {e}");
                continue;
            }
        };
        // A single upload records its category inside the JSON; otherwise
        // fall back to the sync manifest, then a generic bucket.
        let category = value
            .get("category")
            .and_then(|c| c.as_str())
            .and_then(clean_category)
            .or_else(|| sources.iter().find(|s| s.id == id).map(|s| s.category.clone()))
            .unwrap_or_else(|| "Other".to_string());
        let stig: StigData = match serde_json::from_value(value) {
            Ok(s) => s,
            Err(e) => {
                warn!("seed: '{id}' is not valid STIG JSON: {e}");
                continue;
            }
        };
        let catalog = CatalogEntry {
            id: id.to_string(),
            title: if stig.title.is_empty() { id.to_string() } else { stig.title.clone() },
            category,
            version: stig.version.clone(),
            release_info: stig.release_info.clone(),
            rule_count: stig.rules.len() as i32,
            json_path: entry.path().to_string_lossy().into_owned(),
            last_updated: Utc::now(),
        };
        found.push(catalog);
    }
    Ok(found)
}

/// Ids with checklists that the manifest and the seed no longer name.
fn orphaned(ids: &[String], sources: &[StigSource], seed_ids: &HashSet<String>) -> Vec<String> {
    ids.iter()
        .filter(|id| !sources.iter().any(|s| &s.id == *id) && !seed_ids.contains(*id))
        .cloned()
        .collect()
}

/// Warn about catalog ids that have checklists but are no longer produced by
/// the sync manifest or the seed (for example after the id renames in
/// `stig-sources.toml`). Their rows are left alone.
pub async fn warn_orphaned_ids(pool: &PgPool, sources: &[StigSource], seed_dir: Option<&Path>) {
    let ids: Result<Vec<String>, _> = sqlx::query_scalar(
        "SELECT DISTINCT c.stig_id FROM checklists c \
         JOIN stigs_catalog sc ON sc.id = c.stig_id ORDER BY 1",
    )
    .fetch_all(pool)
    .await;
    let Ok(ids) = ids else { return };
    let seed_dir = seed_dir.map(Path::to_path_buf);
    let seed_ids: HashSet<String> = tokio::task::spawn_blocking(move || {
        seed_dir
            .and_then(|d| std::fs::read_dir(d).ok())
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str().and_then(seed_id).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    let orphans = orphaned(&ids, sources, &seed_ids);
    if !orphans.is_empty() {
        let shown: Vec<&str> = orphans.iter().take(50).map(String::as_str).collect();
        warn!(
            "{} catalog id(s) with checklists are no longer in stig-sources.toml or the seed \
             and will not be refreshed by sync: {} (see the README note on renamed ids)",
            orphans.len(),
            shown.join(", ")
        );
    }
}

/// Run both seeding steps; failures are logged, never fatal.
pub async fn seed(seed_dir: &Path, stigs_dir: &Path, pool: &PgPool, sources: &[StigSource]) {
    let (from, to) = (seed_dir.to_path_buf(), stigs_dir.to_path_buf());
    let copied = tokio::task::spawn_blocking(move || copy_missing(&from, &to))
        .await
        .unwrap_or_else(|e| Err(e.into()));
    match copied {
        Ok(n) => info!("seed: copied {n} missing file(s) from {}", seed_dir.display()),
        Err(e) => warn!("seed: copy from {} failed: {e:#}", seed_dir.display()),
    }
    match index_missing(pool, stigs_dir, sources).await {
        Ok(n) => info!("seed: indexed {n} STIG(s) with no catalog row"),
        Err(e) => warn!("seed: catalog indexing failed: {e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Temp directory removed on drop, even when an assertion fails.
    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new() -> Self {
            let d = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn copy_missing_never_overwrites_and_skips_bad_names() {
        let (seed, dest) = (Tmp::new(), Tmp::new());
        std::fs::write(seed.0.join("edge.json"), "seed-edge").unwrap();
        std::fs::write(seed.0.join("new.json"), "seed-new").unwrap();
        std::fs::write(seed.0.join("bad name.json"), "x").unwrap();
        std::fs::write(seed.0.join("notes.txt"), "x").unwrap();
        std::fs::create_dir_all(seed.0.join("archive")).unwrap();
        std::fs::write(dest.0.join("edge.json"), "synced-edge").unwrap();

        assert_eq!(copy_missing(&seed.0, &dest.0).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(dest.0.join("edge.json")).unwrap(), "synced-edge");
        assert_eq!(std::fs::read_to_string(dest.0.join("new.json")).unwrap(), "seed-new");
        assert!(!dest.0.join("bad name.json").exists());
        assert!(!dest.0.join("notes.txt").exists());
        assert!(!dest.0.join("archive").exists());
        // No temp files left behind, and a second pass copies nothing.
        let stray = std::fs::read_dir(&dest.0)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".seed-"))
            .count();
        assert_eq!(stray, 0);
        assert_eq!(copy_missing(&seed.0, &dest.0).unwrap(), 0);
    }

    #[test]
    fn category_from_json_must_be_bounded_and_printable() {
        assert_eq!(clean_category(" Windows "), Some("Windows".into()));
        assert_eq!(clean_category(""), None);
        assert_eq!(clean_category("   "), None);
        assert_eq!(clean_category(&"a".repeat(65)), None);
        assert_eq!(clean_category("a\nb"), None);
    }

    #[test]
    fn orphans_are_ids_missing_from_manifest_and_seed() {
        let src = |id: &str| StigSource {
            id: id.into(), title: "t".into(), category: "c".into(), url: "u".into(),
        };
        let seed: HashSet<String> = ["from-seed".to_string()].into();
        let ids: Vec<String> =
            ["in-manifest", "from-seed", "windows-11"].iter().map(|s| s.to_string()).collect();
        assert_eq!(orphaned(&ids, &[src("in-manifest")], &seed), vec!["windows-11".to_string()]);
    }

    fn stig_json(extra: &str) -> String {
        format!(
            r#"{{"title":"T","description":"","version":"1","releaseInfo":"R","rules":[]{extra}}}"#
        )
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn index_missing_adds_valid_files_only_and_keeps_existing_rows(pool: PgPool) {
        let dir = Tmp::new();
        let w = |n: &str, c: &str| std::fs::write(dir.0.join(n), c).unwrap();
        w("with-json-cat.json", &stig_json(r#","category":"FromJson""#));
        w("with-manifest-cat.json", &stig_json(""));
        w("with-other-cat.json", &stig_json(""));
        w("bad-json-cat.json", &stig_json(&format!(r#","category":"{}""#, "x".repeat(80))));
        w("already-there.json", &stig_json(""));
        w("bad name.json", &stig_json(""));
        w("Upper.json", &stig_json(""));
        w("malformed.json", "{not json");
        sqlx::query(
            "INSERT INTO stigs_catalog (id, title, category, version, release_info, rule_count, json_path) \
             VALUES ('already-there', 'Keep', 'Keep', '9', 'K', 7, 'p')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let sources = vec![
            StigSource { id: "with-manifest-cat".into(), title: "t".into(), category: "Browser".into(), url: "u".into() },
            StigSource { id: "bad-json-cat".into(), title: "t".into(), category: "Network".into(), url: "u".into() },
        ];

        assert_eq!(index_missing(&pool, &dir.0, &sources).await.unwrap(), 4);

        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT id, category, title FROM stigs_catalog ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(
            ids,
            ["already-there", "bad-json-cat", "with-json-cat", "with-manifest-cat", "with-other-cat"]
        );
        let cat = |id: &str| rows.iter().find(|r| r.0 == id).unwrap().1.clone();
        assert_eq!(cat("with-json-cat"), "FromJson");
        assert_eq!(cat("with-manifest-cat"), "Browser");
        assert_eq!(cat("bad-json-cat"), "Network");
        assert_eq!(cat("with-other-cat"), "Other");
        let kept = rows.iter().find(|r| r.0 == "already-there").unwrap();
        assert_eq!((kept.1.as_str(), kept.2.as_str()), ("Keep", "Keep"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn index_missing_skips_files_over_the_size_cap(pool: PgPool) {
        let dir = Tmp::new();
        let small = stig_json("");
        std::fs::write(dir.0.join("small.json"), &small).unwrap();
        std::fs::write(dir.0.join("big.json"), stig_json(&format!(r#","pad":"{}""#, "x".repeat(500)))).unwrap();
        let cap = small.len() as u64 + 10;
        assert_eq!(index_missing_capped(&pool, &dir.0, &[], cap).await.unwrap(), 1);
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM stigs_catalog")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(ids, vec!["small".to_string()]);
    }
}
