use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::{fs, path::PathBuf};

/// True when the deployment is flagged for production (STIG_ENV=production).
/// In production we refuse to silently fall back to dev defaults for
/// secrets / DB URLs — the boot fails loudly instead.
pub fn is_production() -> bool {
    std::env::var("STIG_ENV")
        .map(|v| v == "production")
        .unwrap_or(false)
}

/// One entry from stig-sources.toml — the curated DISA download manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct StigSource {
    pub id: String,
    pub title: String,
    pub category: String,
    pub url: String,
}

/// Top-level structure of stig-sources.toml.
#[derive(Debug, Deserialize)]
struct SourcesFile {
    stigs: Vec<StigSource>,
}

/// Runtime configuration assembled from env vars and the sources manifest.
#[derive(Debug, Clone)]
pub struct Config {
    /// TCP port the Axum server binds to.
    pub port: u16,
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// Root directory for parsed STIG JSON files.
    pub data_dir: PathBuf,
    /// How often the sync scheduler runs (hours).
    pub sync_interval_hours: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // Database URL: in production we refuse to fall back to a dev
        // Postgres on localhost — that's the kind of misconfig that
        // silently boots the wrong stack in CI.
        let database_url = match std::env::var("DATABASE_URL") {
            Ok(v) if !v.trim().is_empty() => v,
            _ if is_production() => {
                return Err(anyhow!(
                    "DATABASE_URL is required when STIG_ENV=production"
                ));
            }
            _ => "postgres://stig:stig_local@localhost:5432/stig_viewer".into(),
        };

        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("PORT must be a valid port number")?,
            database_url,
            data_dir: PathBuf::from(
                std::env::var("DATA_DIR").unwrap_or_else(|_| "data".into()),
            ),
            sync_interval_hours: std::env::var("STIG_SYNC_INTERVAL_HOURS")
                .unwrap_or_else(|_| "24".into())
                .parse()
                .context("STIG_SYNC_INTERVAL_HOURS must be a positive integer")?,
        })
    }
}

/// Load and parse `stig-sources.toml` from the current directory.
pub fn load_sources() -> Result<Vec<StigSource>> {
    let raw = fs::read_to_string("stig-sources.toml")
        .context("Cannot read stig-sources.toml — run from the backend/ directory")?;
    let parsed: SourcesFile =
        toml::from_str(&raw).context("Failed to parse stig-sources.toml")?;
    Ok(parsed.stigs)
}
