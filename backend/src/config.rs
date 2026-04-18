use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::PathBuf};

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
    /// Maximum bytes accepted by `POST /api/upload` (single STIG ZIP).
    pub max_upload_bytes: usize,
    /// Maximum bytes accepted by `POST /api/upload/library` (DISA library bundle).
    pub max_library_bytes: usize,
    /// Per-IP upload rate limit: requests per minute.
    pub upload_rate_per_min: u32,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // DATABASE_URL is required. No hardcoded fallback: a wrong default in
        // production is worse than a loud failure at startup.
        let database_url = std::env::var("DATABASE_URL").context(
            "DATABASE_URL is required (e.g. postgres://user:pass@host:5432/stig_viewer). \
             See .env.example.",
        )?;

        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("PORT must be a valid port number")?,
            database_url,
            data_dir: PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "data".into())),
            sync_interval_hours: std::env::var("STIG_SYNC_INTERVAL_HOURS")
                .unwrap_or_else(|_| "24".into())
                .parse()
                .context("STIG_SYNC_INTERVAL_HOURS must be a positive integer")?,
            max_upload_bytes: parse_bytes_env("MAX_UPLOAD_BYTES", 50 * 1024 * 1024)?,
            max_library_bytes: parse_bytes_env("MAX_LIBRARY_BYTES", 500 * 1024 * 1024)?,
            upload_rate_per_min: std::env::var("UPLOAD_RATE_PER_MIN")
                .unwrap_or_else(|_| "10".into())
                .parse()
                .context("UPLOAD_RATE_PER_MIN must be a non-negative integer")?,
        })
    }
}

fn parse_bytes_env(key: &str, default: usize) -> Result<usize> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<usize>()
            .with_context(|| format!("{key} must be a non-negative integer (bytes)")),
        Err(_) => Ok(default),
    }
}

/// Load and parse `stig-sources.toml` from the current directory.
pub fn load_sources() -> Result<Vec<StigSource>> {
    let raw = fs::read_to_string("stig-sources.toml")
        .context("Cannot read stig-sources.toml — run from the backend/ directory")?;
    let parsed: SourcesFile = toml::from_str(&raw).context("Failed to parse stig-sources.toml")?;
    Ok(parsed.stigs)
}
