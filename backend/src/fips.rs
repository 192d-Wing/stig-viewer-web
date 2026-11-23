//! FIPS startup guard and pending-algorithm policy (#64, #70).
//!
//! With `--features fips` the backend refuses to start unless the AWS-LC FIPS
//! module is linked and reports FIPS mode. The AWS-LC-FIPS 4.x module as a
//! whole is pending CMVP validation (in process, no certificate claimed); the
//! per-algorithm list below is an additional gate. Application crypto and TLS
//! do not use the module yet.
//!
//! `STIG_REQUIRE_FIPS` makes a non-`fips` build refuse to start. One
//! `system.fips_policy` audit event is written at server startup.
//!
//! `X25519MLKEM768` is the hybrid group for the transition period; CNSA 2.0
//! deployments need `ML-KEM-1024`.

use std::collections::BTreeSet;

use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};

use crate::db_audit::{record_system_now, NewSystemEvent};

pub const PENDING_ALGS_ENV: &str = "STIG_FIPS_PENDING_ALGS";
pub const REQUIRE_FIPS_ENV: &str = "STIG_REQUIRE_FIPS";
pub const POLICY_ACTION: &str = "system.fips_policy";

/// Bound on the startup audit write, so a hung pool cannot stall startup.
const POLICY_EVENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse `STIG_REQUIRE_FIPS`: unset/blank/0/false is off, 1/true is on, and
/// anything else is an error (a typo must not silently disable the guard).
pub fn parse_require_fips(raw: Option<&str>) -> Result<bool> {
    let v = raw.unwrap_or("").trim();
    if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") {
        Ok(false)
    } else if v == "1" || v.eq_ignore_ascii_case("true") {
        Ok(true)
    } else {
        anyhow::bail!(
            "{REQUIRE_FIPS_ENV} has invalid value {raw:?}; use 1 to require a FIPS build or leave it unset"
        )
    }
}

/// True when built with `--features fips`.
pub const fn compiled() -> bool {
    cfg!(feature = "fips")
}

/// Algorithms pending FIPS validation that a FIPS build refuses unless opted
/// in. The module as a whole is pending CMVP validation; this list is an
/// additional per-algorithm gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PendingAlg {
    MlDsa87,
    MlKem768,
    MlKem1024,
    X25519MlKem768,
}

impl PendingAlg {
    pub const ALL: &[PendingAlg] = &[
        PendingAlg::MlDsa87,
        PendingAlg::MlKem768,
        PendingAlg::MlKem1024,
        PendingAlg::X25519MlKem768,
    ];

    pub const fn token(self) -> &'static str {
        match self {
            PendingAlg::MlDsa87 => "ML-DSA-87",
            PendingAlg::MlKem768 => "ML-KEM-768",
            PendingAlg::MlKem1024 => "ML-KEM-1024",
            PendingAlg::X25519MlKem768 => "X25519MLKEM768",
        }
    }
}

/// Parse the comma-separated allow-list. Unset/blank is the empty set; empty
/// items are ignored; an unknown token is an error.
pub fn parse_pending_algs(raw: Option<&str>) -> Result<BTreeSet<PendingAlg>> {
    let mut out = BTreeSet::new();
    for item in raw.unwrap_or("").split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        match PendingAlg::ALL
            .iter()
            .find(|a| a.token().eq_ignore_ascii_case(item))
        {
            Some(a) => {
                out.insert(*a);
            }
            None => {
                let valid: Vec<&str> = PendingAlg::ALL.iter().map(|a| a.token()).collect();
                anyhow::bail!(
                    "{PENDING_ALGS_ENV} has unknown algorithm {item:?}; valid tokens: {}",
                    valid.join(", ")
                );
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsPolicy {
    enforced: bool,
    allowed_pending: BTreeSet<PendingAlg>,
}

impl FipsPolicy {
    pub fn from_vars(enforced: bool, pending: Option<&str>) -> Result<Self> {
        Ok(Self {
            enforced,
            allowed_pending: parse_pending_algs(pending)?,
        })
    }

    pub fn enforced(&self) -> bool {
        self.enforced
    }

    pub fn allowed_pending(&self) -> impl Iterator<Item = PendingAlg> + '_ {
        self.allowed_pending.iter().copied()
    }

    #[allow(dead_code)] // first caller is #65
    pub fn permits(&self, alg: PendingAlg) -> bool {
        !self.enforced || self.allowed_pending.contains(&alg)
    }

    #[allow(dead_code)] // first caller is #65
    pub fn require(&self, alg: PendingAlg) -> Result<()> {
        if self.permits(alg) {
            Ok(())
        } else {
            anyhow::bail!(
                "{} is pending FIPS validation and is not listed in {PENDING_ALGS_ENV}",
                alg.token()
            )
        }
    }
}

/// Pure guard: when enforced, any probe error stops startup.
/// Returns whether the probe ran and passed (false when not enforced).
pub fn check_module(enforced: bool, probe: impl FnOnce() -> Result<(), String>) -> Result<bool> {
    if !enforced {
        return Ok(false);
    }
    probe().map_err(|e| anyhow::anyhow!("refusing to start: FIPS module check failed: {e}"))?;
    Ok(true)
}

#[cfg(feature = "fips")]
fn real_probe() -> Result<(), String> {
    aws_lc_rs::try_fips_mode().map_err(|e| e.to_string())
}

#[cfg(not(feature = "fips"))]
fn real_probe() -> Result<(), String> {
    Err("not built with the fips feature".to_string())
}

/// True when a non-FIPS build was given a pending-algorithm list, which does
/// not change behaviour there (it is still validated).
fn warn_list_ignored(policy: &FipsPolicy) -> bool {
    !policy.enforced() && policy.allowed_pending().next().is_some()
}

/// What startup decided; the facts the `system.fips_policy` event records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsStartup {
    pub policy: FipsPolicy,
    /// Built with the `fips` feature.
    pub compiled: bool,
    /// The probe ran and reported FIPS mode.
    pub mode_active: bool,
    /// `STIG_REQUIRE_FIPS` was set.
    pub require_fips: bool,
}

impl FipsStartup {
    pub fn audit_detail(&self) -> Value {
        let algs: Vec<&str> = self
            .policy
            .allowed_pending()
            .map(PendingAlg::token)
            .collect();
        json!({
            "fipsCompiled": self.compiled,
            "fipsModeActive": self.mode_active,
            "requireFips": self.require_fips,
            // Static until #65 moves application crypto into the module:
            // fipsModeActive does not mean app crypto is FIPS-covered.
            "appCryptoInModule": false,
            "pendingAlgs": algs,
        })
    }
}

/// Pure core of [`startup_guard`]: the module check runs only after both
/// variables parse and the require-FIPS check passes.
fn guard(
    compiled: bool,
    raw_require: Option<&str>,
    raw_pending: Option<&str>,
    probe: impl FnOnce() -> Result<(), String>,
) -> Result<FipsStartup> {
    let require_fips = parse_require_fips(raw_require)?;
    let policy = FipsPolicy::from_vars(compiled, raw_pending)?;
    if require_fips && !compiled {
        anyhow::bail!(
            "refusing to start: {REQUIRE_FIPS_ENV} is set but this binary was built without the fips feature; deploy a --features fips build or unset {REQUIRE_FIPS_ENV}"
        );
    }
    let mode_active = check_module(compiled, probe)?;
    Ok(FipsStartup {
        policy,
        compiled,
        mode_active,
        require_fips,
    })
}

/// Parse the policy, run the module check, log, and return the result.
pub fn startup_guard() -> Result<FipsStartup> {
    let raw_require = std::env::var(REQUIRE_FIPS_ENV).ok();
    let raw_pending = std::env::var(PENDING_ALGS_ENV).ok();
    let startup = match guard(
        compiled(),
        raw_require.as_deref(),
        raw_pending.as_deref(),
        real_probe,
    ) {
        Ok(s) => s,
        Err(e) => {
            // No pool exists yet, so the log line is the record.
            tracing::error!(
                target: "audit",
                action = POLICY_ACTION,
                outcome = "failure",
                "FIPS startup guard refused to start (no audit row written): {e:#}"
            );
            return Err(e);
        }
    };
    let policy = &startup.policy;
    if policy.enforced() {
        #[cfg(feature = "fips")]
        tracing::info!(
            module_version = aws_lc_rs::awslc_version(),
            require_fips = startup.require_fips,
            pending_algs = ?policy.allowed_pending().map(PendingAlg::token).collect::<Vec<_>>(),
            "AWS-LC FIPS module linked and reporting FIPS mode"
        );
        for alg in policy.allowed_pending() {
            tracing::warn!(
                algorithm = alg.token(),
                "pending algorithm opted in via {PENDING_ALGS_ENV}"
            );
        }
        tracing::warn!(
            "the linked AWS-LC-FIPS 4.x module is pending CMVP validation (in process); no CMVP certificate is claimed for this build"
        );
        tracing::warn!(
            "application crypto and TLS do not yet use the FIPS module; this is not a compliance claim"
        );
    } else {
        tracing::info!(require_fips = false, "FIPS mode: not compiled in");
        if warn_list_ignored(policy) {
            tracing::warn!(
                "{PENDING_ALGS_ENV} does not change which algorithms are used in a non-FIPS build"
            );
        }
    }
    Ok(startup)
}

async fn try_record_policy_event(
    pool: &sqlx::PgPool,
    s: &FipsStartup,
    timeout: Duration,
) -> Result<Result<()>, tokio::time::error::Elapsed> {
    let ev = NewSystemEvent {
        action: POLICY_ACTION,
        outcome: "ok",
        stig_id: None,
        detail: s.audit_detail(),
    };
    tokio::time::timeout(timeout, record_system_now(pool, ev)).await
}

/// Write the one `system.fips_policy` event for this server start. A failed
/// write is logged and startup continues.
pub async fn record_policy_event(pool: &sqlx::PgPool, s: &FipsStartup) {
    let _ = record_policy_event_with_timeout(pool, s, POLICY_EVENT_TIMEOUT).await;
}

async fn record_policy_event_with_timeout(
    pool: &sqlx::PgPool,
    s: &FipsStartup,
    timeout: Duration,
) -> Option<&'static str> {
    let (audit_write, err) = match try_record_policy_event(pool, s, timeout).await {
        Ok(Ok(())) => return None,
        Ok(Err(e)) => ("failed", format!("{e:#}")),
        Err(_) => ("timeout", "timed out".to_string()),
    };
    tracing::error!(
        target: "audit",
        action = POLICY_ACTION,
        outcome = "failure",
        audit_write,
        policy_outcome = "ok",
        fips_compiled = s.compiled,
        fips_mode_active = s.mode_active,
        require_fips = s.require_fips,
        pending_algs = ?s.policy.allowed_pending().map(PendingAlg::token).collect::<Vec<_>>(),
        "audit write failed: {err}"
    );
    Some(audit_write)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(raw: &str) -> BTreeSet<PendingAlg> {
        parse_pending_algs(Some(raw)).unwrap()
    }

    #[test]
    fn empty_inputs_give_empty_set() {
        assert!(parse_pending_algs(None).unwrap().is_empty());
        assert!(p("").is_empty());
        assert!(p("  ").is_empty());
    }

    #[test]
    fn parses_tokens_leniently() {
        assert_eq!(p("ML-DSA-87"), BTreeSet::from([PendingAlg::MlDsa87]));
        assert_eq!(
            p(" ml-dsa-87 , X25519mlkem768 "),
            BTreeSet::from([PendingAlg::MlDsa87, PendingAlg::X25519MlKem768])
        );
        assert_eq!(
            p("ML-KEM-768,ml-kem-768,"),
            BTreeSet::from([PendingAlg::MlKem768])
        );
    }

    #[test]
    fn unknown_tokens_are_errors() {
        for bad in ["ML-DSA-65", "all", "*", "ML-DSA-87,bogus"] {
            let e = parse_pending_algs(Some(bad)).unwrap_err().to_string();
            assert!(e.contains(PENDING_ALGS_ENV), "{e}");
        }
        let e = parse_pending_algs(Some("all")).unwrap_err().to_string();
        assert!(e.contains("\"all\"") && e.contains("ML-KEM-768"), "{e}");
    }

    #[test]
    fn every_token_round_trips() {
        for a in PendingAlg::ALL {
            assert_eq!(p(a.token()), BTreeSet::from([*a]));
        }
    }

    #[test]
    fn non_enforced_permits_everything() {
        for list in [None, Some("ML-DSA-87")] {
            let pol = FipsPolicy::from_vars(false, list).unwrap();
            for a in PendingAlg::ALL {
                assert!(pol.permits(*a));
                assert!(pol.require(*a).is_ok());
            }
        }
    }

    #[test]
    fn enforced_refuses_unless_listed() {
        let pol = FipsPolicy::from_vars(true, None).unwrap();
        for a in PendingAlg::ALL {
            assert!(!pol.permits(*a));
            let e = pol.require(*a).unwrap_err().to_string();
            assert!(e.contains(a.token()) && e.contains(PENDING_ALGS_ENV), "{e}");
        }
        let pol = FipsPolicy::from_vars(true, Some("ML-KEM-768")).unwrap();
        assert!(pol.permits(PendingAlg::MlKem768));
        assert!(!pol.permits(PendingAlg::MlDsa87));
        assert_eq!(
            pol.allowed_pending().collect::<Vec<_>>(),
            [PendingAlg::MlKem768]
        );
    }

    #[test]
    fn bad_token_errors_either_way() {
        assert!(FipsPolicy::from_vars(true, Some("nope")).is_err());
        assert!(FipsPolicy::from_vars(false, Some("nope")).is_err());
    }

    #[test]
    fn check_module_cases() {
        assert!(!check_module(false, || panic!("probe must not run")).unwrap());
        assert!(check_module(true, || Ok(())).unwrap());
        let e = check_module(true, || Err("boom".into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("refusing to start") && e.contains("boom"), "{e}");
    }

    #[test]
    fn guard_with_failing_probe_is_err_when_enforced() {
        let e = guard(true, None, Some("ML-DSA-87"), || Err("boom".into())).unwrap_err();
        assert!(e.to_string().contains("refusing to start"));
        let ok = guard(false, None, Some("ML-DSA-87"), || {
            panic!("probe must not run")
        })
        .unwrap();
        assert!(!ok.policy.enforced());
        let ok = guard(true, None, None, || Ok(())).unwrap();
        assert!(ok.policy.enforced());
        assert!(guard(false, None, Some("nope"), || Ok(())).is_err());
    }

    #[test]
    fn list_ignored_warning_decision() {
        let listed = FipsPolicy::from_vars(false, Some("ML-DSA-87")).unwrap();
        let empty = FipsPolicy::from_vars(false, None).unwrap();
        let enforced = FipsPolicy::from_vars(true, Some("ML-DSA-87")).unwrap();
        assert!(warn_list_ignored(&listed));
        assert!(!warn_list_ignored(&empty));
        assert!(!warn_list_ignored(&enforced));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn startup_guard_enforces_in_fips_build() {
        assert!(startup_guard().unwrap().policy.enforced());
        let s = guard(compiled(), None, None, real_probe).unwrap();
        assert!(s.policy.enforced() && s.mode_active && s.compiled);
    }

    #[test]
    fn require_fips_parses_valid_values() {
        for v in [None, Some(""), Some("  "), Some("0"), Some("false")] {
            assert!(!parse_require_fips(v).unwrap(), "{v:?}");
        }
        for v in ["1", " 1 ", "true", "TRUE"] {
            assert!(parse_require_fips(Some(v)).unwrap(), "{v:?}");
        }
    }

    #[test]
    fn require_fips_rejects_invalid_values() {
        for v in ["yes", "2", "on", "1,1"] {
            let e = parse_require_fips(Some(v)).unwrap_err().to_string();
            assert!(
                e.contains(REQUIRE_FIPS_ENV) && e.contains(&format!("{v:?}")),
                "{e}"
            );
        }
    }

    #[test]
    fn require_fips_without_feature_refuses() {
        let e = guard(false, Some("1"), None, || panic!("probe must not run"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("refusing to start") && e.contains(REQUIRE_FIPS_ENV),
            "{e}"
        );
    }

    #[test]
    fn require_fips_with_feature_passes() {
        let s = guard(true, Some("1"), None, || Ok(())).unwrap();
        assert!(s.require_fips && s.compiled && s.mode_active);
    }

    #[test]
    fn require_unset_is_unchanged() {
        let s = guard(false, None, Some("ML-DSA-87"), || {
            panic!("probe must not run")
        })
        .unwrap();
        assert!(!s.require_fips && !s.compiled && !s.mode_active);
    }

    #[test]
    fn invalid_require_value_fails_in_both_builds() {
        for compiled in [true, false] {
            assert!(guard(compiled, Some("maybe"), None, || panic!(
                "probe must not run"
            ))
            .is_err());
        }
    }

    #[test]
    fn require_set_does_not_mask_probe_failure() {
        let e = guard(true, Some("1"), None, || Err("boom".into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("FIPS module check failed"), "{e}");
    }

    #[test]
    fn audit_detail_shape() {
        let s = guard(false, None, None, || Ok(())).unwrap();
        assert_eq!(
            s.audit_detail(),
            json!({"fipsCompiled": false, "fipsModeActive": false, "requireFips": false, "appCryptoInModule": false, "pendingAlgs": []})
        );
        let s = guard(false, None, Some("ML-DSA-87"), || Ok(())).unwrap();
        assert_eq!(
            s.audit_detail(),
            json!({"fipsCompiled": false, "fipsModeActive": false, "requireFips": false, "appCryptoInModule": false, "pendingAlgs": ["ML-DSA-87"]})
        );
        let s = guard(true, Some("1"), Some("X25519MLKEM768,ml-dsa-87"), || Ok(())).unwrap();
        assert_eq!(
            s.audit_detail(),
            json!({"fipsCompiled": true, "fipsModeActive": true, "requireFips": true, "appCryptoInModule": false, "pendingAlgs": ["ML-DSA-87", "X25519MLKEM768"]})
        );
    }

    #[tokio::test]
    async fn an_unreachable_database_does_not_stop_startup() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(300))
            .connect_lazy("postgres://127.0.0.1:1/x")
            .unwrap();
        let s = guard(false, None, None, || Ok(())).unwrap();
        let r = record_policy_event_with_timeout(&pool, &s, Duration::from_secs(2)).await;
        assert_eq!(r, Some("failed"));
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_policy_event_is_one_system_row(pool: sqlx::PgPool) {
        let s = FipsStartup {
            policy: FipsPolicy::from_vars(true, Some("ML-DSA-87,ML-KEM-768")).unwrap(),
            compiled: true,
            mode_active: true,
            require_fips: true,
        };
        try_record_policy_event(&pool, &s, POLICY_EVENT_TIMEOUT)
            .await
            .unwrap()
            .unwrap();
        let rows: Vec<(String, Value)> = sqlx::query_as(
            "SELECT outcome, detail FROM audit_events \
             WHERE action = $1 AND user_id IS NULL AND user_role = 'system'",
        )
        .bind(POLICY_ACTION)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "ok");
        assert_eq!(rows[0].1, s.audit_detail());
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_build_module_is_in_fips_mode() {
        assert!(compiled());
        assert!(real_probe().is_ok());
        assert!(aws_lc_rs::try_fips_mode().is_ok());
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn default_build_is_not_enforced() {
        assert!(!compiled());
        let pol = FipsPolicy::from_vars(compiled(), None).unwrap();
        assert!(PendingAlg::ALL.iter().all(|a| pol.permits(*a)));
    }
}
