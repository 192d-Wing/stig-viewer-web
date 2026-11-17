use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::Instant,
};

use axum::{
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;

use crate::api::auth::AuthUser;

/// Per-user token bucket. `tokens` is a float so partial refills don't get
/// silently truncated between requests fired faster than 1/sec.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BucketState {
    pub tokens: f64,
    pub last_refill: Instant,
}

/// In-memory map: user.id -> bucket. We pick `Mutex<HashMap>` over a third-
/// party concurrent map (e.g. dashmap) to avoid adding a new dep just for
/// this — the critical section is a tiny arithmetic update and the lock is
/// only held for the duration of refill + check + decrement.
pub(crate) static BUCKETS: LazyLock<Mutex<HashMap<String, BucketState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Most keys kept by the pre-auth limiter (one slot is reserved for [`OVERFLOW_KEY`]).
const PRE_AUTH_MAX_KEYS: usize = 10_000;
/// Minimum time between full-map prunes, so a flood of fresh keys cannot force
/// an O(n) scan per request.
const PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// Shared bucket for fresh keys once the map is full (fail-shared: the overflow
/// clients compete for one budget; keys already tracked keep theirs).
const OVERFLOW_KEY: &str = "overflow";

struct LimiterInner {
    map: HashMap<String, BucketState>,
    last_prune: Instant,
    last_overflow_warn: Option<Instant>,
    prunes: u32,
}

/// Per-key token bucket for the unauthenticated auth endpoints.
pub(crate) struct PreAuthLimiter {
    inner: Mutex<LimiterInner>,
    capacity: f64,
    refill_per_sec: f64,
    max_keys: usize,
}

impl PreAuthLimiter {
    pub(crate) fn new(capacity: f64, refill_per_sec: f64, max_keys: usize) -> Self {
        Self {
            inner: Mutex::new(LimiterInner { map: HashMap::new(), last_prune: Instant::now(), last_overflow_warn: None, prunes: 0 }),
            capacity,
            refill_per_sec,
            max_keys: max_keys.max(2),
        }
    }

    /// From the raw `AUTH_RATE_LIMIT_BURST` / `AUTH_RATE_LIMIT_PER_MINUTE` values.
    pub(crate) fn from_vars(burst: Option<&str>, per_minute: Option<&str>) -> Self {
        let parse = |v: Option<&str>, d: f64| {
            v.and_then(|s| s.parse::<f64>().ok()).filter(|x| *x > 0.0).unwrap_or(d)
        };
        Self::new(parse(burst, 30.0), parse(per_minute, 60.0) / 60.0, PRE_AUTH_MAX_KEYS)
    }

    fn from_env() -> Self {
        Self::from_vars(
            std::env::var("AUTH_RATE_LIMIT_BURST").ok().as_deref(),
            std::env::var("AUTH_RATE_LIMIT_PER_MINUTE").ok().as_deref(),
        )
    }

    pub(crate) fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    pub(crate) fn allow_at(&self, key: &str, now: Instant) -> bool {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let inner = &mut *g;
        let mut key = key;
        if !inner.map.contains_key(key) && key != OVERFLOW_KEY && inner.map.len() + 1 >= self.max_keys {
            if now.saturating_duration_since(inner.last_prune) >= PRUNE_INTERVAL {
                inner.last_prune = now;
                inner.prunes += 1;
                let (cap, refill) = (self.capacity, self.refill_per_sec);
                // Drop buckets that have fully refilled (they carry no state).
                inner.map.retain(|_, b| {
                    let el = now.saturating_duration_since(b.last_refill).as_secs_f64();
                    b.tokens + el * refill < cap
                });
            }
            if inner.map.len() + 1 >= self.max_keys {
                key = OVERFLOW_KEY;
                let due = inner
                    .last_overflow_warn
                    .is_none_or(|t| now.saturating_duration_since(t) >= std::time::Duration::from_secs(60));
                if due {
                    inner.last_overflow_warn = Some(now);
                    tracing::warn!("pre-auth rate limiter is full; new clients share the overflow bucket");
                }
            }
        }
        let capacity = self.capacity;
        let bucket = inner
            .map
            .entry(key.to_string())
            .or_insert(BucketState { tokens: capacity, last_refill: now });
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }

    fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.map.clear();
        }
    }
}

static PRE_AUTH: LazyLock<PreAuthLimiter> = LazyLock::new(PreAuthLimiter::from_env);

/// Limiter key for a canonical IP: IPv4 (and IPv4-mapped IPv6) by full address,
/// other IPv6 by its /64 prefix, anything else (empty) as `"unknown"`.
pub(crate) fn limiter_key(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.to_string(),
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{}/64", std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        Err(_) => "unknown".to_string(),
    }
}

/// The process-wide limiter (env read once).
pub(crate) fn global() -> &'static PreAuthLimiter {
    &PRE_AUTH
}

/// Per-IP limit for `/auth/notice/ack`, `/auth/login` and `/auth/saml/login`.
/// Env (read once): `AUTH_RATE_LIMIT_BURST` (default 30), `AUTH_RATE_LIMIT_PER_MINUTE` (default 60).
pub(crate) fn allow_pre_auth(ip: &str) -> bool {
    PRE_AUTH.allow(&limiter_key(ip))
}

/// Capacity (max burst) — env `RATE_LIMIT_BURST`, default 20.
fn burst() -> f64 {
    std::env::var("RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(20.0)
}

/// Refill — env `RATE_LIMIT_PER_MINUTE` tokens / 60s, default 60.
fn refill_per_second() -> f64 {
    let per_min = std::env::var("RATE_LIMIT_PER_MINUTE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(60.0);
    per_min / 60.0
}

/// True for methods that don't consume tokens. Mirrors the safe-method set
/// the existing `viewer_guard` middleware already lets through.
fn is_read_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// True for paths that are exempt from rate limiting regardless of method.
/// `/api/test/*` is only registered when `STIG_ENABLE_TEST_ROUTES=true`,
/// so this only matters in dev / CI — but it's important there: the
/// reset-db + seed helpers fire from E2E setup and we don't want a noisy
/// spec to eat into the next spec's budget.
fn is_exempt_path(path: &str) -> bool {
    path.starts_with("/api/test/")
}

/// Clear the bucket map. Used by the test-only reset endpoint so the E2E
/// rate-limit spec doesn't bleed across runs or get poisoned by earlier
/// specs that did heavy mutation work.
pub fn reset() {
    if let Ok(mut map) = BUCKETS.lock() {
        map.clear();
    }
    PRE_AUTH.clear();
}

/// Token-bucket rate limiter middleware. Sits AFTER `auth_middleware` on
/// the protected router so `Extension<AuthUser>` is populated. Returns
/// 429 with `Retry-After: 1` + a small JSON body when a user exceeds
/// their burst.
pub async fn rate_limit(
    Extension(user): Extension<AuthUser>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Pass-throughs:
    //  - reads (GET/HEAD/OPTIONS) — these don't mutate anything and we
    //    don't want to throttle a dashboard refresh.
    //  - admin role — already trusted to do bulk work (imports, etc.)
    //  - /api/test/* — E2E setup paths.
    if is_read_method(&method) || user.role == "admin" || is_exempt_path(&path) {
        return next.run(req).await;
    }

    let capacity = burst();
    let refill = refill_per_second();
    let now = Instant::now();

    // Hold the lock just long enough to refill + decide. We do NOT await
    // `next.run` while holding it — that would block every other user.
    let allowed = {
        let mut map = match BUCKETS.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let bucket = map.entry(user.id.clone()).or_insert(BucketState {
            tokens: capacity,
            last_refill: now,
        });

        // Refill based on elapsed time since the last touch. Cap at capacity
        // so a long-idle user can't accumulate an unbounded burst.
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * refill).min(capacity);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    };

    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "1")],
            Json(json!({ "error": "rate limit exceeded" })),
        )
            .into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod pre_auth_tests {
    use super::*;

    #[test]
    fn burst_then_deny_with_separate_budget_per_key() {
        let l = PreAuthLimiter::from_vars(Some("3"), Some("60"));
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(l.allow_at("1.1.1.1", t0));
        }
        assert!(!l.allow_at("1.1.1.1", t0));
        assert!(l.allow_at("2.2.2.2", t0));
        assert!(l.allow_at("1.1.1.1", t0 + std::time::Duration::from_secs(2)));
    }

    #[test]
    fn map_never_exceeds_cap_and_overflow_is_shared() {
        let l = PreAuthLimiter::new(2.0, 0.0, 50);
        let t0 = Instant::now();
        for i in 0..500 {
            l.allow_at(&format!("10.0.{}.{}", i / 250, i % 250), t0);
            assert!(l.len() <= 50);
        }
        // Keys past the cap share the overflow budget (2 tokens), so most are denied.
        let denied = (500..520).filter(|i| !l.allow_at(&format!("10.9.0.{i}"), t0)).count();
        assert!(denied >= 18);
    }

    fn prunes(l: &PreAuthLimiter) -> u32 {
        l.inner.lock().map(|g| g.prunes).unwrap_or(0)
    }

    #[test]
    fn prune_runs_at_most_once_per_interval() {
        let l = PreAuthLimiter::new(2.0, 1.0, 4);
        let t0 = Instant::now();
        for k in ["k0", "k1", "k2"] {
            l.allow_at(k, t0);
        }
        let s = std::time::Duration::from_secs;
        // Long after: everything refilled, the first fresh key prunes and fits.
        assert!(l.allow_at("a", t0 + s(60)));
        assert_eq!(prunes(&l), 1);
        l.allow_at("b", t0 + s(60));
        l.allow_at("c", t0 + s(60));
        // Map is full again; inside the interval no second scan happens.
        l.allow_at("d", t0 + s(61));
        assert_eq!(prunes(&l), 1);
        assert!(l.len() <= 4);
        // After the interval the next fresh key may scan again.
        l.allow_at("e", t0 + s(71));
        assert_eq!(prunes(&l), 2);
    }

    #[test]
    fn ipv6_shares_a_bucket_per_64_and_ipv4_is_exact() {
        assert_eq!(limiter_key("2001:db8:1:2::1"), limiter_key("2001:db8:1:2:ffff::9"));
        assert_ne!(limiter_key("2001:db8:1:2::1"), limiter_key("2001:db8:1:3::1"));
        assert_eq!(limiter_key("::ffff:1.2.3.4"), "1.2.3.4");
        assert_eq!(limiter_key("1.2.3.4"), "1.2.3.4");
        assert_ne!(limiter_key("1.2.3.4"), limiter_key("1.2.3.5"));
        assert_eq!(limiter_key(""), "unknown");
    }
}
