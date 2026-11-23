//! FIPS startup guard and pending-algorithm policy (#64, #70).
//!
//! With `--features fips` the backend refuses to start unless the AWS-LC FIPS
//! module is linked and reports FIPS mode. That proves the module is present;
//! it does not mean application crypto or TLS use it yet.
//!
//! `X25519MLKEM768` is the hybrid group for the transition period; CNSA 2.0
//! deployments need `ML-KEM-1024`.

use std::collections::BTreeSet;

use anyhow::Result;

pub const PENDING_ALGS_ENV: &str = "STIG_FIPS_PENDING_ALGS";

/// True when built with `--features fips`.
pub const fn compiled() -> bool {
    cfg!(feature = "fips")
}

/// Algorithms not yet FIPS-validated that a FIPS build refuses unless opted in.
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
                "{} is not FIPS-validated yet and is not listed in {PENDING_ALGS_ENV}",
                alg.token()
            )
        }
    }
}

/// Pure guard: when enforced, any probe error stops startup.
pub fn check_module(enforced: bool, probe: impl FnOnce() -> Result<(), String>) -> Result<()> {
    if !enforced {
        return Ok(());
    }
    probe().map_err(|e| anyhow::anyhow!("refusing to start: FIPS module check failed: {e}"))
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

/// Pure core of [`startup_guard`]: the policy is built only after the module
/// check passes.
fn guard(
    enforced: bool,
    raw_pending: Option<&str>,
    probe: impl FnOnce() -> Result<(), String>,
) -> Result<FipsPolicy> {
    let policy = FipsPolicy::from_vars(enforced, raw_pending)?;
    check_module(enforced, probe)?;
    Ok(policy)
}

/// Parse the policy, run the module check, log, and return the policy.
pub fn startup_guard() -> Result<FipsPolicy> {
    let raw = std::env::var(PENDING_ALGS_ENV).ok();
    let policy = guard(compiled(), raw.as_deref(), real_probe)?;
    if policy.enforced() {
        #[cfg(feature = "fips")]
        tracing::info!(
            module_version = aws_lc_rs::awslc_version(),
            pending_algs = ?policy.allowed_pending().map(PendingAlg::token).collect::<Vec<_>>(),
            "AWS-LC FIPS module linked and in FIPS mode"
        );
        for alg in policy.allowed_pending() {
            tracing::warn!(
                algorithm = alg.token(),
                "pending algorithm opted in via {PENDING_ALGS_ENV}"
            );
        }
        tracing::warn!(
            "application crypto and TLS do not yet use the FIPS module; this is not a compliance claim"
        );
    } else {
        tracing::info!("FIPS mode: not compiled in");
        if warn_list_ignored(&policy) {
            tracing::warn!(
                "{PENDING_ALGS_ENV} does not change which algorithms are used in a non-FIPS build"
            );
        }
    }
    Ok(policy)
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
        assert!(check_module(false, || panic!("probe must not run")).is_ok());
        assert!(check_module(true, || Ok(())).is_ok());
        let e = check_module(true, || Err("boom".into()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("refusing to start") && e.contains("boom"), "{e}");
    }

    #[test]
    fn guard_with_failing_probe_is_err_when_enforced() {
        let e = guard(true, Some("ML-DSA-87"), || Err("boom".into())).unwrap_err();
        assert!(e.to_string().contains("refusing to start"));
        let ok = guard(false, Some("ML-DSA-87"), || panic!("probe must not run")).unwrap();
        assert!(!ok.enforced());
        let ok = guard(true, None, || Ok(())).unwrap();
        assert!(ok.enforced());
        assert!(guard(false, Some("nope"), || Ok(())).is_err());
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
        assert!(startup_guard().unwrap().enforced());
        assert!(guard(compiled(), None, real_probe).unwrap().enforced());
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
