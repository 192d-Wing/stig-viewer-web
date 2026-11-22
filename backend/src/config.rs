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
#[derive(Clone)]
pub struct Config {
    /// TCP port the Axum server binds to.
    pub port: u16,
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// `DATABASE_MIGRATION_URL`: optional owner-role URL used only to run
    /// migrations and apply the app role's grants. Never logged.
    pub database_migration_url: Option<String>,
    /// Root directory for parsed STIG JSON files.
    pub data_dir: PathBuf,
    /// How often the sync scheduler runs (hours).
    pub sync_interval_hours: u64,
    /// `BACKUP_REQUIRE_SIGNATURE`: `None` means the default, which is to
    /// require a verified signature exactly when `SIGNING_KEY_HEX` is set.
    pub backup_require_signature: Option<bool>,
    /// Run a DISA sync as soon as the server starts (`STIG_SYNC_ON_START`,
    /// default true). The periodic schedule is unaffected.
    pub sync_on_start: bool,
    /// Dev-only read-only directory of seed STIG JSON (`STIG_SEED_DIR`).
    /// Missing files are copied into `data_dir/stigs` at start; unset in
    /// production.
    pub seed_dir: Option<PathBuf>,
}

/// Debug never prints the connection URLs (they can carry passwords).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("database_url", &"<redacted>")
            .field(
                "database_migration_url",
                &self.database_migration_url.as_ref().map(|_| "<redacted>"),
            )
            .field("data_dir", &self.data_dir)
            .field("sync_interval_hours", &self.sync_interval_hours)
            .field("backup_require_signature", &self.backup_require_signature)
            .field("sync_on_start", &self.sync_on_start)
            .field("seed_dir", &self.seed_dir)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()
                .context("PORT must be a valid port number")?,
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://stig:stig_local@localhost:5432/stig_viewer".into()),
            database_migration_url: parse_migration_url(
                std::env::var("DATABASE_MIGRATION_URL").ok().as_deref(),
            ),
            data_dir: PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "data".into())),
            sync_interval_hours: std::env::var("STIG_SYNC_INTERVAL_HOURS")
                .unwrap_or_else(|_| "24".into())
                .parse()
                .context("STIG_SYNC_INTERVAL_HOURS must be a positive integer")?,
            backup_require_signature: parse_require_signature(
                std::env::var("BACKUP_REQUIRE_SIGNATURE").ok().as_deref(),
            )?,
            sync_on_start: parse_flag_default_true(
                std::env::var("STIG_SYNC_ON_START").ok().as_deref(),
            ),
            seed_dir: parse_seed_dir(std::env::var("STIG_SEED_DIR").ok().as_deref()),
        })
    }
}

/// `DATABASE_MIGRATION_URL`: unset, empty or whitespace is `None`.
pub fn parse_migration_url(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// `BACKUP_REQUIRE_SIGNATURE`: `true`/`1`/`yes`, `false`/`0`/`no` (trimmed,
/// case-insensitive); unset means the default (`None`). Anything else is an
/// error, so a typo cannot silently weaken or change the policy.
pub fn parse_require_signature(raw: Option<&str>) -> Result<Option<bool>> {
    match raw.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        None => Ok(None),
        Some("true" | "1" | "yes") => Ok(Some(true)),
        Some("false" | "0" | "no") => Ok(Some(false)),
        Some(other) => anyhow::bail!(
            "BACKUP_REQUIRE_SIGNATURE must be true/1/yes or false/0/no (got {other:?})"
        ),
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

/// Opt-out boolean env value: on unless explicitly `false` / `0` (trimmed,
/// case-insensitive), so unset, empty or a typo keeps the default behaviour.
pub fn parse_flag_default_true(raw: Option<&str>) -> bool {
    !matches!(
        raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("false") | Some("0")
    )
}

/// `STIG_SEED_DIR` value: unset, empty or whitespace-only means no seeding.
pub fn parse_seed_dir(raw: Option<&str>) -> Option<PathBuf> {
    raw.filter(|v| !v.trim().is_empty()).map(PathBuf::from)
}

/// Startup guard: `STIG_SEED_DIR` is a dev-only convenience, so a production
/// deployment that sets it refuses to start (like [`TestHooks::validate`]).
pub fn validate_seed_dir(stig_env: Option<&str>, seed_dir: Option<&std::path::Path>) -> Result<()> {
    if is_production(stig_env) && seed_dir.is_some() {
        anyhow::bail!(
            "refusing to start: STIG_SEED_DIR must not be set when STIG_ENV=production \
             (it is a dev-only seeding hook)"
        );
    }
    Ok(())
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

/// Parse an integer env value within `min..=max`. Unset, empty or whitespace
/// gives `default`; anything else that is not an integer in range is an error
/// naming the variable, so a typo on a security limit cannot be ignored.
pub fn parse_bounded(
    name: &str,
    raw: Option<&str>,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64> {
    let Some(v) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(default);
    };
    match v.parse::<u64>() {
        Ok(n) if (min..=max).contains(&n) => Ok(n),
        _ => anyhow::bail!("{name} must be an integer from {min} to {max} (got {v:?})"),
    }
}

/// `ADMISSION_BODY_MIN_RATE_KIB` bounds (KiB/s).
pub const ADMISSION_BODY_MIN_RATE_KIB_BOUNDS: (u64, u64) = (8, 8192);
/// `ADMISSION_BODY_GRACE_SECS` bounds.
pub const ADMISSION_BODY_GRACE_SECS_BOUNDS: (u64, u64) = (1, 120);
/// `ADMISSION_BODY_FIRST_BYTE_SECS` bounds.
pub const ADMISSION_BODY_FIRST_BYTE_SECS_BOUNDS: (u64, u64) = (1, 60);

/// Time a body reader gets to receive its first byte, from the first time the
/// handler reads the body (a handler that does other work first is not
/// charged for it). Past it the body yields an error (the extractor answers
/// 400) and the handler returns, releasing the permit.
pub const DEFAULT_ADMISSION_BODY_FIRST_BYTE: std::time::Duration =
    std::time::Duration::from_secs(5);
/// After the first byte: time allowed on top of the rate rule. The deadline
/// is `first_byte_at + grace + bytes / min_rate`.
pub const DEFAULT_ADMISSION_BODY_GRACE: std::time::Duration = std::time::Duration::from_secs(10);
/// Minimum average body rate in bytes per second; each byte received extends
/// the deadline by `1 / min_rate` seconds.
pub const DEFAULT_ADMISSION_BODY_MIN_RATE: u64 = 64 * 1024;

/// Request-body deadlines for admitted requests (see `api::admission`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionBody {
    /// Time allowed for the first byte.
    pub first_byte: std::time::Duration,
    /// Time allowed on top of the rate rule once the first byte arrived.
    pub grace: std::time::Duration,
    /// Minimum average body rate, bytes per second.
    pub min_rate: u64,
}

impl AdmissionBody {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|n| std::env::var(n).ok())
    }

    /// Reads the three `ADMISSION_BODY_*` variables through `get`.
    ///
    /// `main` calls `from_env()?` before the database is opened or a port
    /// bound, so an `Err` here stops startup; that `?` is the only untested
    /// step (#175).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        Self::from_vars(
            get("ADMISSION_BODY_FIRST_BYTE_SECS").as_deref(),
            get("ADMISSION_BODY_GRACE_SECS").as_deref(),
            get("ADMISSION_BODY_MIN_RATE_KIB").as_deref(),
        )
    }

    pub fn from_vars(
        first_byte_secs: Option<&str>,
        grace_secs: Option<&str>,
        min_rate_kib: Option<&str>,
    ) -> Result<Self> {
        let (fb_min, fb_max) = ADMISSION_BODY_FIRST_BYTE_SECS_BOUNDS;
        let (gr_min, gr_max) = ADMISSION_BODY_GRACE_SECS_BOUNDS;
        let (rt_min, rt_max) = ADMISSION_BODY_MIN_RATE_KIB_BOUNDS;
        let first_byte = parse_bounded(
            "ADMISSION_BODY_FIRST_BYTE_SECS",
            first_byte_secs,
            DEFAULT_ADMISSION_BODY_FIRST_BYTE.as_secs(),
            fb_min,
            fb_max,
        )?;
        let grace = parse_bounded(
            "ADMISSION_BODY_GRACE_SECS",
            grace_secs,
            DEFAULT_ADMISSION_BODY_GRACE.as_secs(),
            gr_min,
            gr_max,
        )?;
        let rate_kib = parse_bounded(
            "ADMISSION_BODY_MIN_RATE_KIB",
            min_rate_kib,
            DEFAULT_ADMISSION_BODY_MIN_RATE / 1024,
            rt_min,
            rt_max,
        )?;
        Ok(Self {
            first_byte: std::time::Duration::from_secs(first_byte),
            grace: std::time::Duration::from_secs(grace),
            min_rate: rate_kib * 1024,
        })
    }
}

/// Load and parse `stig-sources.toml` from the current directory.
pub fn load_sources() -> Result<Vec<StigSource>> {
    let raw = fs::read_to_string("stig-sources.toml")
        .context("Cannot read stig-sources.toml — run from the backend/ directory")?;
    let parsed: SourcesFile = toml::from_str(&raw).context("Failed to parse stig-sources.toml")?;
    Ok(parsed.stigs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_body_defaults_when_unset_or_blank() {
        for raw in [None, Some(""), Some("  ")] {
            let b = AdmissionBody::from_vars(raw, raw, raw).unwrap();
            assert_eq!(b.first_byte, DEFAULT_ADMISSION_BODY_FIRST_BYTE);
            assert_eq!(b.grace, DEFAULT_ADMISSION_BODY_GRACE);
            assert_eq!(b.min_rate, DEFAULT_ADMISSION_BODY_MIN_RATE);
        }
    }

    #[test]
    fn a_bad_admission_body_env_value_is_an_error_naming_the_variable() {
        use std::collections::HashMap;
        let names = [
            "ADMISSION_BODY_FIRST_BYTE_SECS",
            "ADMISSION_BODY_GRACE_SECS",
            "ADMISSION_BODY_MIN_RATE_KIB",
        ];
        for bad_name in names {
            for bad in ["0", "abc"] {
                let m: HashMap<&str, String> = [(bad_name, bad.to_string())].into();
                let err = AdmissionBody::from_lookup(|n| m.get(n).cloned()).unwrap_err();
                assert!(
                    format!("{err:#}").contains(bad_name),
                    "{bad_name}={bad}: {err:#}"
                );
            }
        }
        let m: HashMap<&str, String> = [
            (names[0], "2".to_string()),
            (names[1], "30".to_string()),
            (names[2], "128".to_string()),
        ]
        .into();
        let b = AdmissionBody::from_lookup(|n| m.get(n).cloned()).unwrap();
        assert_eq!(b.first_byte, std::time::Duration::from_secs(2));
        assert_eq!(b.grace, std::time::Duration::from_secs(30));
        assert_eq!(b.min_rate, 128 * 1024);
    }

    #[test]
    fn admission_body_accepts_overrides_within_bounds() {
        let b = AdmissionBody::from_vars(Some("2"), Some(" 30 "), Some("128")).unwrap();
        assert_eq!(b.first_byte, std::time::Duration::from_secs(2));
        assert_eq!(b.grace, std::time::Duration::from_secs(30));
        assert_eq!(b.min_rate, 128 * 1024);
        let lo = AdmissionBody::from_vars(Some("1"), Some("1"), Some("8")).unwrap();
        assert_eq!(lo.min_rate, 8 * 1024);
        assert_eq!(lo.first_byte, std::time::Duration::from_secs(1));
        let hi = AdmissionBody::from_vars(Some("60"), Some("120"), Some("8192")).unwrap();
        assert_eq!(hi.min_rate, 8192 * 1024);
        assert_eq!(hi.grace, std::time::Duration::from_secs(120));
    }

    #[test]
    fn admission_body_rejects_out_of_range_and_garbage() {
        for bad in ["0", "7", "8193", "-1", "64k", "1.5"] {
            let err = AdmissionBody::from_vars(None, None, Some(bad))
                .unwrap_err()
                .to_string();
            assert!(err.contains("ADMISSION_BODY_MIN_RATE_KIB"), "{bad}: {err}");
        }
        let err = AdmissionBody::from_vars(Some("61"), None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ADMISSION_BODY_FIRST_BYTE_SECS"), "{err}");
        let err = AdmissionBody::from_vars(None, Some("121"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ADMISSION_BODY_GRACE_SECS"), "{err}");
    }

    #[test]
    fn require_signature_accepts_only_explicit_booleans() {
        assert_eq!(parse_require_signature(None).unwrap(), None);
        for on in ["true", "1", "YES", " yes "] {
            assert_eq!(
                parse_require_signature(Some(on)).unwrap(),
                Some(true),
                "{on:?}"
            );
        }
        for off in ["false", "0", "No", " false "] {
            assert_eq!(
                parse_require_signature(Some(off)).unwrap(),
                Some(false),
                "{off:?}"
            );
        }
        for bad in ["", "on", "tru", "2", "enabled"] {
            assert!(parse_require_signature(Some(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn shipped_sources_manifest_is_valid_and_unique() {
        // cargo test runs from backend/, where the manifest lives.
        let sources = load_sources().expect("stig-sources.toml parses");
        assert!(!sources.is_empty());
        let mut seen = std::collections::HashSet::new();
        for s in &sources {
            assert!(crate::stig_id::is_valid_new(&s.id), "bad id {}", s.id);
            assert!(seen.insert(s.id.clone()), "duplicate id {}", s.id);
            assert!(s.url.starts_with("https://dl.dod.cyber.mil/"), "{}", s.url);
        }
        // The e2e suite reads these two from the seed.
        assert!(seen.contains("edge") && seen.contains("windows-10"));
    }

    #[test]
    fn config_debug_redacts_database_urls() {
        // Built at runtime so no credential-shaped literal sits in the source.
        let url = |user: &str, pw: &str| format!("postgres://{user}:{pw}@h/d");
        let c = Config {
            port: 1,
            database_url: url("u", "secret1"),
            database_migration_url: Some(url("o", "secret2")),
            data_dir: PathBuf::new(),
            sync_interval_hours: 1,
            backup_require_signature: None,
            sync_on_start: false,
            seed_dir: None,
        };
        let d = format!("{c:?}");
        assert!(!d.contains("secret1") && !d.contains("secret2"), "{d}");
    }

    #[test]
    fn migration_url_empty_or_blank_is_none() {
        assert_eq!(parse_migration_url(None), None);
        assert_eq!(parse_migration_url(Some("")), None);
        assert_eq!(parse_migration_url(Some("  \t")), None);
        assert_eq!(
            parse_migration_url(Some(" postgres://o@h/d ")),
            Some("postgres://o@h/d".to_string())
        );
    }

    #[test]
    fn seed_dir_empty_or_blank_is_none() {
        assert_eq!(parse_seed_dir(None), None);
        assert_eq!(parse_seed_dir(Some("")), None);
        assert_eq!(parse_seed_dir(Some("  \t")), None);
        assert_eq!(
            parse_seed_dir(Some("/app/data")),
            Some(PathBuf::from("/app/data"))
        );
    }

    #[test]
    fn production_refuses_seed_dir() {
        let dir = std::path::Path::new("/seed");
        assert!(validate_seed_dir(Some(" Production "), Some(dir)).is_err());
        assert!(validate_seed_dir(Some("production"), None).is_ok());
        assert!(validate_seed_dir(Some("development"), Some(dir)).is_ok());
        assert!(validate_seed_dir(None, Some(dir)).is_ok());
    }

    #[test]
    fn sync_on_start_defaults_on_and_only_false_or_zero_disable() {
        assert!(parse_flag_default_true(None));
        for on in ["", "true", "1", "yes", "tru"] {
            assert!(parse_flag_default_true(Some(on)), "{on:?}");
        }
        for off in ["false", "FALSE", " false ", "0"] {
            assert!(!parse_flag_default_true(Some(off)), "{off:?}");
        }
    }

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
        for env in [
            None,
            Some(""),
            Some("prod"),
            Some("producton"),
            Some("development"),
        ] {
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
        for (routes, header) in [
            (None, None),
            (Some("false"), Some("0")),
            (Some(""), Some("no")),
        ] {
            assert!(TestHooks::from_vars(Some("production"), routes, header)
                .validate()
                .is_ok());
        }
    }
}
