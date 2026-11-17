use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::PgPool;
use std::{path::Path, sync::Arc};
use tracing::{error, info, warn};

use crate::{
    config::{Config, StigSource},
    db::{upsert_catalog, CatalogEntry},
    parser::{extract_xccdf_from_zip, parse_xccdf},
};

/// Reject a source whose id is not a valid new STIG id, before any I/O.
fn validate_source(source: &StigSource) -> Result<()> {
    if !crate::stig_id::is_valid_new(&source.id) {
        anyhow::bail!(
            "STIG id {:?} is invalid (1-{} lower-case ASCII letters, digits or hyphens); skipped",
            source.id.chars().take(64).collect::<String>(),
            crate::stig_id::MAX_BYTES
        );
    }
    Ok(())
}

/// What happened to one source in a sync pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Downloaded, parsed and indexed (the file may or may not have changed).
    Synced,
    /// DISA answered 404 or 410: the URL in stig-sources.toml is out of date.
    StaleUrl,
}

/// Totals for one sync pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub synced: usize,
    pub stale: usize,
    pub errors: usize,
}

impl SyncSummary {
    /// One-line description for the scheduler log.
    pub fn describe(&self) -> String {
        format!(
            "synced {}, {} stale URL(s), {} error(s)",
            self.synced, self.stale, self.errors
        )
    }
}

/// A 404 or 410 means the manifest URL has gone stale (DISA publishes a new
/// file name per release); every other non-success status is a real error.
fn is_stale_status(status: u16) -> bool {
    matches!(status, 404 | 410)
}

/// True when the file on disk already holds exactly the new bytes.
fn is_unchanged(existing: Option<&[u8]>, new: &[u8]) -> bool {
    existing == Some(new)
}

/// Download, parse, and index one STIG from DISA.
async fn sync_one(
    source: &StigSource,
    client: &reqwest::Client,
    pool: &PgPool,
    data_dir: &Path,
) -> Result<Outcome> {
    validate_source(source)?;
    info!("Syncing STIG '{}' from {}", source.id, source.url);

    // 1. Download ZIP
    let resp = client
        .get(&source.url)
        .send()
        .await
        .context("HTTP request failed")?;

    if is_stale_status(resp.status().as_u16()) {
        warn!(
            "source '{}' URL not found (HTTP {}); update stig-sources.toml",
            source.id,
            resp.status().as_u16()
        );
        return Ok(Outcome::StaleUrl);
    }
    if !resp.status().is_success() {
        anyhow::bail!("DISA returned HTTP {}", resp.status());
    }

    let zip_bytes = resp.bytes().await.context("Failed to read response body")?;

    // 2. Extract XCCDF XML from ZIP (handles double-zipped STIGs)
    let xccdf =
        extract_xccdf_from_zip(&zip_bytes).context("Failed to extract XCCDF from ZIP")?;

    // 3. Parse XCCDF → StigData
    let stig = parse_xccdf(&xccdf).context("Failed to parse XCCDF")?;

    // 4. Write JSON file
    let stigs_dir = data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await?;
    let json_path = stigs_dir.join(format!("{}.json", source.id));

    let json_str = serde_json::to_string(&stig)?;

    // 4a. Identical bytes: nothing to write and nothing to archive. (The
    //     catalog row is still upserted below so a reset database re-indexes.)
    let existing = tokio::fs::read(&json_path).await.ok();
    let unchanged = is_unchanged(existing.as_deref(), json_str.as_bytes());

    // 4b. If a previous JSON already exists for this STIG, archive it
    //     under stigs/archive/ keyed by the OLD version + release so the
    //     diff endpoint can compare current vs prior. We look up the
    //     pre-sync catalog row to capture the about-to-be-replaced
    //     metadata.
    if !unchanged && existing.is_some() {
        if let Err(e) =
            archive_previous_catalog(pool, data_dir, &source.id, &json_path).await
        {
            // Archive failures are non-fatal — log and continue so a
            // disk hiccup or unique-constraint race doesn't stop the
            // actual sync from updating the live catalog.
            warn!("Failed to archive previous version of '{}': {e:#}", source.id);
        }
    }

    if unchanged {
        info!("'{}' unchanged; not rewritten", source.id);
    } else {
        tokio::fs::write(&json_path, json_str.as_bytes()).await?;
        info!("Wrote '{}'", json_path.display());
    }

    // 5. Upsert catalog row in Postgres
    let entry = CatalogEntry {
        id: source.id.clone(),
        // Prefer title parsed from XCCDF; fall back to the manifest title
        title: if stig.title.is_empty() { source.title.clone() } else { stig.title.clone() },
        category: source.category.clone(),
        version: stig.version.clone(),
        release_info: stig.release_info.clone(),
        rule_count: stig.rules.len() as i32,
        json_path: json_path.to_string_lossy().into_owned(),
        last_updated: Utc::now(),
    };
    upsert_catalog(pool, &entry)
        .await
        .context("Failed to upsert catalog entry")?;

    info!(
        "Synced '{}': {} rules → {}",
        source.id,
        stig.rules.len(),
        json_path.display()
    );
    Ok(Outcome::Synced)
}

/// Copy `${data_dir}/stigs/{id}.json` to
/// `${data_dir}/stigs/archive/{id}-v{version}-r{release_safe}.json`
/// and insert a `catalog_archive` row pointing at that file. Uses the
/// stigs_catalog row's CURRENT values (which are about to be replaced)
/// as the archived version/release. Safe to call when no catalog row
/// exists yet — early-returns with Ok.
async fn archive_previous_catalog(
    pool: &PgPool,
    data_dir: &Path,
    stig_id: &str,
    current_json: &Path,
) -> Result<()> {
    // Fetch the about-to-be-replaced version + release from the catalog.
    // If no row exists yet (first ever sync) there's nothing to archive.
    let row: Option<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT version, release_info FROM stigs_catalog WHERE id = $1",
    )
    .bind(stig_id)
    .fetch_optional(pool)
    .await?;

    let Some((old_version, old_release)) = row else {
        return Ok(());
    };

    let archive_dir = data_dir.join("stigs").join("archive");
    tokio::fs::create_dir_all(&archive_dir).await?;

    let archive_name = archive_file_name(stig_id, &old_version, &old_release);
    let archive_abs = archive_dir.join(&archive_name);

    // Copy the file regardless — if a previous archive run already
    // wrote it we'll either overwrite identical bytes (no-op) or pick
    // up corruption from a half-written prior copy and replace it. The
    // DB insert below is the source of truth for whether we're done.
    tokio::fs::copy(current_json, &archive_abs).await?;

    // Relative path under data_dir so the row is portable across
    // deployments / mount points. matches the convention used by the
    // existing stigs_catalog.json_path field.
    let rel_path = format!("stigs/archive/{archive_name}");

    let res = sqlx::query(
        r#"
        INSERT INTO catalog_archive (stig_id, version, release_info, json_path)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (stig_id, version, release_info) DO NOTHING
        "#,
    )
    .bind(stig_id)
    .bind(&old_version)
    .bind(&old_release)
    .bind(&rel_path)
    .execute(pool)
    .await?;

    if res.rows_affected() == 0 {
        info!(
            "Archive already exists for '{}' v{} ({}) — skipped",
            stig_id, old_version, old_release
        );
    } else {
        info!(
            "Archived previous '{}' v{} ({}) → {}",
            stig_id,
            old_version,
            old_release,
            archive_abs.display()
        );
    }
    Ok(())
}

/// Archive file name for a replaced STIG version. The sanitised version and
/// release are readable but lossy (`1.2` and `1-2` agree), so a hash of the
/// raw pair keeps distinct versions from overwriting each other.
pub(crate) fn archive_file_name(stig_id: &str, version: &str, release_info: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(version.as_bytes());
    h.update([0u8]);
    h.update(release_info.as_bytes());
    let digest = h.finalize();
    let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!(
        "{stig_id}-v{}-r{}-{short}.json",
        sanitize_release(version),
        sanitize_release(release_info)
    )
}

/// Replace whitespace and other filesystem-unfriendly characters in a
/// release_info string so it can be embedded in an archive filename.
///
/// `"Release: 4 Benchmark Date: 09 Apr 2026"` → `"Release-4-Benchmark-Date-09-Apr-2026"`.
fn sanitize_release(release_info: &str) -> String {
    let mut out = String::with_capacity(release_info.len());
    let mut prev_dash = false;
    for c in release_info.chars() {
        if c.is_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// Run one full sync pass across all STIG sources.
pub async fn run_sync(
    config: &Arc<Config>,
    sources: &Arc<Vec<StigSource>>,
    pool: &PgPool,
) -> Result<SyncSummary> {
    let client = reqwest::Client::builder()
        .user_agent("stig-viewer-backend/0.1")
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut summary = SyncSummary::default();
    for source in sources.as_ref() {
        match sync_one(source, &client, pool, &config.data_dir).await {
            Ok(Outcome::Synced) => summary.synced += 1,
            Ok(Outcome::StaleUrl) => summary.stale += 1,
            Err(e) => {
                error!("Failed to sync '{}': {e:#}", source.id);
                summary.errors += 1;
            }
        }
    }

    if summary.errors == 0 && summary.stale == 0 {
        info!("Sync complete — {}", summary.describe());
    } else {
        warn!(
            "Sync finished: {} (of {} sources)",
            summary.describe(),
            sources.len()
        );
    }
    Ok(summary)
}

#[cfg(test)]
mod id_tests {
    use super::*;

    fn src(id: &str) -> StigSource {
        StigSource { id: id.into(), title: "t".into(), category: "c".into(), url: "u".into() }
    }

    #[test]
    fn archive_names_differ_for_colliding_versions() {
        let a = archive_file_name("x", "1.2", "R 1");
        let b = archive_file_name("x", "1-2", "R 1");
        let c = archive_file_name("x", "1.2", "R-1");
        assert!(a.starts_with("x-v1-2-rR-1-") && a.ends_with(".json"));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, archive_file_name("x", "1.2", "R 1"));
    }

    #[test]
    fn only_404_and_410_are_stale() {
        assert!(is_stale_status(404));
        assert!(is_stale_status(410));
        for other in [200, 301, 403, 429, 500, 502, 503] {
            assert!(!is_stale_status(other), "{other}");
        }
    }

    #[test]
    fn summary_counts_stale_separately() {
        let s = SyncSummary { synced: 5, stale: 2, errors: 1 };
        assert_eq!(s.describe(), "synced 5, 2 stale URL(s), 1 error(s)");
    }

    #[test]
    fn unchanged_only_when_bytes_equal() {
        assert!(is_unchanged(Some(b"one"), b"one"));
        assert!(!is_unchanged(Some(b"one"), b"two"));
        assert!(!is_unchanged(None, b"one"), "a missing file is a change");
        assert!(!is_unchanged(None, b""));
    }

    #[test]
    fn validate_source_rejects_bad_ids() {
        for bad in ["../x", "a.b", "a b", "", "Upper", "é"] {
            assert!(validate_source(&src(bad)).is_err(), "{bad}");
        }
        assert!(validate_source(&src("windows-10")).is_ok());
        assert!(validate_source(&src("a")).is_ok());
    }
}
