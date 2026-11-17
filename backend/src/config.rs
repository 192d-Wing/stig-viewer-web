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
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("PORT must be a valid port number")?,
            database_url: std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                "postgres://stig:stig_local@localhost:5432/stig_viewer".into()
            }),
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

/// Parse an opt-in boolean env value. Only `true` / `1` (trimmed,
/// case-insensitive) switch a flag on; unset, empty or anything else is off,
/// so a typo can never enable a test hook by accident.
pub fn parse_flag(raw: Option<&str>) -> bool {
    matches!(
        raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("true") | Some("1")
    )
}

/// True when `STIG_ENV` names production (trimmed, case-insensitive).
pub fn is_production(stig_env: Option<&str>) -> bool {
    stig_env
        .map(|v| v.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

/// Test-only hooks. Both are off unless explicitly enabled, and
/// [`TestHooks::validate`] refuses to start a production deployment with
/// either of them on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestHooks {
    /// `STIG_ENV=production`.
    pub production: bool,
    /// `STIG_ENABLE_TEST_ROUTES` — mount the unauthenticated `/api/test/*`
    /// router (DB reset, role changes, session minting, ...).
    pub enable_test_routes: bool,
    /// `ALLOW_TEST_AUTH_HEADER` — accept `X-User-Id` in place of a session.
    pub allow_test_auth_header: bool,
}

impl TestHooks {
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok();
        Self::from_vars(
            var("STIG_ENV").as_deref(),
            var("STIG_ENABLE_TEST_ROUTES").as_deref(),
            var("ALLOW_TEST_AUTH_HEADER").as_deref(),
        )
    }

    pub fn from_vars(
        stig_env: Option<&str>,
        enable_test_routes: Option<&str>,
        allow_test_auth_header: Option<&str>,
    ) -> Self {
        Self {
            production: is_production(stig_env),
            enable_test_routes: parse_flag(enable_test_routes),
            allow_test_auth_header: parse_flag(allow_test_auth_header),
        }
    }

    /// Startup guard: error out if a test hook is enabled in production.
    pub fn validate(&self) -> Result<()> {
        if !self.production {
            return Ok(());
        }
        let mut offending = Vec::new();
        if self.enable_test_routes {
            offending.push("STIG_ENABLE_TEST_ROUTES");
        }
        if self.allow_test_auth_header {
            offending.push("ALLOW_TEST_AUTH_HEADER");
        }
        if offending.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "refusing to start: {} must not be set when STIG_ENV=production \
                 (these enable unauthenticated test-only access)",
                offending.join(" and ")
            )
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flag_is_off_unless_explicitly_true() {
        for on in ["true", "1", "TRUE", " true ", "True"] {
            assert!(parse_flag(Some(on)), "{on:?} should enable");
        }
        for off in ["", "0", "false", "yes", "on", "enabled", "tru", "2"] {
            assert!(!parse_flag(Some(off)), "{off:?} should not enable");
        }
        assert!(!parse_flag(None));
    }

    #[test]
    fn is_production_matches_only_production() {
        assert!(is_production(Some("production")));
        assert!(is_production(Some(" Production ")));
        assert!(is_production(Some("PRODUCTION")));
        for other in ["", "prod", "development", "staging", "producton"] {
            assert!(!is_production(Some(other)), "{other:?}");
        }
        assert!(!is_production(None));
    }

    #[test]
    fn hooks_default_to_off_with_nothing_set() {
        let hooks = TestHooks::from_vars(None, None, None);
        assert_eq!(
            hooks,
            TestHooks {
                production: false,
                enable_test_routes: false,
                allow_test_auth_header: false,
            }
        );
        assert!(hooks.validate().is_ok());
    }

    #[test]
    fn unset_or_misspelled_env_does_not_enable_test_routes() {
        // The old gate was `STIG_ENV != "production"`: any of these exposed
        // /api/test/*. None of them may do so now.
        for env in [None, Some(""), Some("prod"), Some("producton"), Some("development")] {
            let hooks = TestHooks::from_vars(env, None, None);
            assert!(!hooks.enable_test_routes, "{env:?}");
            assert!(!hooks.allow_test_auth_header, "{env:?}");
        }
    }

    #[test]
    fn each_flag_parses_independently() {
        let routes = TestHooks::from_vars(Some("development"), Some("true"), None);
        assert!(routes.enable_test_routes && !routes.allow_test_auth_header);
        let header = TestHooks::from_vars(Some("development"), Some("false"), Some("1"));
        assert!(!header.enable_test_routes && header.allow_test_auth_header);
        assert!(routes.validate().is_ok());
        assert!(header.validate().is_ok());
    }

    #[test]
    fn hooks_are_allowed_outside_production() {
        for env in [None, Some("development"), Some("ci")] {
            let hooks = TestHooks::from_vars(env, Some("true"), Some("true"));
            assert!(hooks.validate().is_ok(), "{env:?}");
        }
    }

    #[test]
    fn production_refuses_test_routes() {
        let err = TestHooks::from_vars(Some("production"), Some("true"), None)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("STIG_ENABLE_TEST_ROUTES"), "{err}");
        assert!(!err.contains("ALLOW_TEST_AUTH_HEADER"), "{err}");
    }

    #[test]
    fn production_refuses_test_auth_header() {
        let err = TestHooks::from_vars(Some("production"), None, Some("1"))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("ALLOW_TEST_AUTH_HEADER"), "{err}");
        assert!(!err.contains("STIG_ENABLE_TEST_ROUTES"), "{err}");
    }

    #[test]
    fn production_refusal_names_both_flags_and_ignores_case() {
        let err = TestHooks::from_vars(Some(" Production"), Some("TRUE"), Some("true"))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("STIG_ENABLE_TEST_ROUTES"), "{err}");
        assert!(err.contains("ALLOW_TEST_AUTH_HEADER"), "{err}");
    }

    #[test]
    fn production_with_hooks_off_starts() {
        for (routes, header) in [(None, None), (Some("false"), Some("0")), (Some(""), Some("no"))] {
            assert!(TestHooks::from_vars(Some("production"), routes, header)
                .validate()
                .is_ok());
        }
    }
}
