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
use std::{io::ErrorKind, path::Path};
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

/// Copy every `{id}.json` from `seed_dir` into `stigs_dir` that is not
/// already there. Returns how many were copied. Symlinks, subdirectories
/// and names that are not valid STIG ids are ignored.
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
        let dest = stigs_dir.join(name);
        // create_new refuses an existing file, so nothing is overwritten
        // even if one appears between a check and the write.
        let mut out = match std::fs::OpenOptions::new().write(true).create_new(true).open(&dest) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        };
        let mut src = std::fs::File::open(entry.path())?;
        std::io::copy(&mut src, &mut out)?;
        copied += 1;
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
    let mut added = 0;
    for entry in std::fs::read_dir(stigs_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(seed_id) else { continue };
        let exists: Option<(String,)> =
            sqlx::query_as("SELECT id FROM stigs_catalog WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        if exists.is_some() {
            continue;
        }
        let bytes = match std::fs::read(entry.path()) {
            Ok(b) => b,
            Err(e) => {
                warn!("seed: cannot read '{id}': {e}");
                continue;
            }
        };
        let stig: StigData = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!("seed: '{id}' is not valid STIG JSON: {e}");
                continue;
            }
        };
        // A single upload records its category inside the JSON; otherwise
        // fall back to the sync manifest, then a generic bucket.
        let category = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("category").and_then(|c| c.as_str().map(str::to_owned)))
            .or_else(|| sources.iter().find(|s| s.id == id).map(|s| s.category.clone()))
            .unwrap_or_else(|| "Other".to_string());
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
        upsert_catalog(pool, &catalog).await?;
        added += 1;
    }
    Ok(added)
}

/// Run both seeding steps; failures are logged, never fatal.
pub async fn seed(seed_dir: &Path, stigs_dir: &Path, pool: &PgPool, sources: &[StigSource]) {
    match copy_missing(seed_dir, stigs_dir) {
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

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn copy_missing_never_overwrites_and_skips_bad_names() {
        let (seed, dest) = (tmp(), tmp());
        std::fs::write(seed.join("edge.json"), "seed-edge").unwrap();
        std::fs::write(seed.join("new.json"), "seed-new").unwrap();
        std::fs::write(seed.join("bad name.json"), "x").unwrap();
        std::fs::write(seed.join("notes.txt"), "x").unwrap();
        std::fs::create_dir_all(seed.join("archive")).unwrap();
        std::fs::write(dest.join("edge.json"), "synced-edge").unwrap();

        assert_eq!(copy_missing(&seed, &dest).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(dest.join("edge.json")).unwrap(), "synced-edge");
        assert_eq!(std::fs::read_to_string(dest.join("new.json")).unwrap(), "seed-new");
        assert!(!dest.join("bad name.json").exists());
        assert!(!dest.join("notes.txt").exists());
        assert!(!dest.join("archive").exists());
        // A second pass copies nothing.
        assert_eq!(copy_missing(&seed, &dest).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&seed);
        let _ = std::fs::remove_dir_all(&dest);
    }
}
