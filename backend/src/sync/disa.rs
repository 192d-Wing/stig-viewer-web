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

/// Download, parse, and index one STIG from DISA.
async fn sync_one(
    source: &StigSource,
    client: &reqwest::Client,
    pool: &PgPool,
    data_dir: &Path,
) -> Result<()> {
    info!("Syncing STIG '{}' from {}", source.id, source.url);

    // 1. Download ZIP
    let resp = client
        .get(&source.url)
        .send()
        .await
        .context("HTTP request failed")?;

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

    // 4a. If a previous JSON already exists for this STIG, archive it
    //     under stigs/archive/ keyed by the OLD version + release so the
    //     diff endpoint can compare current vs prior. We look up the
    //     pre-sync catalog row to capture the about-to-be-replaced
    //     metadata.
    if tokio::fs::try_exists(&json_path).await.unwrap_or(false) {
        if let Err(e) =
            archive_previous_catalog(pool, data_dir, &source.id, &json_path).await
        {
            // Archive failures are non-fatal — log and continue so a
            // disk hiccup or unique-constraint race doesn't stop the
            // actual sync from updating the live catalog.
            warn!("Failed to archive previous version of '{}': {e:#}", source.id);
        }
    }

    let json_str = serde_json::to_string(&stig)?;
    tokio::fs::write(&json_path, json_str).await?;

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
    Ok(())
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

    let release_safe = sanitize_release(&old_release);
    let archive_name = format!("{stig_id}-v{old_version}-r{release_safe}.json");
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
) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("stig-viewer-backend/0.1")
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut errors = 0usize;
    for source in sources.as_ref() {
        if let Err(e) = sync_one(source, &client, pool, &config.data_dir).await {
            error!("Failed to sync '{}': {e:#}", source.id);
            errors += 1;
        }
    }

    if errors == 0 {
        info!("Sync complete — {} STIGs updated", sources.len());
    } else {
        warn!(
            "Sync finished with {errors} error(s) out of {} STIGs",
            sources.len()
        );
    }
    Ok(())
}
