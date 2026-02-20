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
