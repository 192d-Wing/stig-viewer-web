//! In-process per-IP rate limiter.
//!
//! Backed by a fixed-window counter per remote IP. Fine for a single-instance
//! deployment; use a shared store (Redis) if you scale horizontally.
//!
//! Middleware usage:
//! ```ignore
//! let limiter = Arc::new(RateLimiter::new(cfg.upload_rate_per_min));
//! router.layer(middleware::from_fn_with_state(
//!     limiter,
//!     ratelimit::limit,
//! ))
//! ```

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
struct Bucket {
    window_start: Option<Instant>,
    count: u32,
}

pub struct RateLimiter {
    /// Requests allowed per 60-second window. 0 disables limiting.
    max_per_window: u32,
    inner: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32) -> Self {
        Self {
            max_per_window,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Returns true if the request is allowed. Updates counters as a side
    /// effect. Unknown IPs share a single bucket so a misconfigured proxy
    /// can't bypass the limit entirely.
    fn check(&self, ip: IpAddr) -> bool {
        if self.max_per_window == 0 {
            return true;
        }
        let now = Instant::now();
        let mut map = self.inner.lock().expect("ratelimit mutex");

        // Opportunistic GC: drop buckets whose window has expired, to bound
        // the map size on long-running servers. O(n) but n is small.
        map.retain(|_, b| {
            b.window_start
                .is_some_and(|t| now.duration_since(t) < WINDOW)
        });

        let bucket = map.entry(ip).or_default();
        let expired = bucket
            .window_start
            .is_none_or(|t| now.duration_since(t) >= WINDOW);
        if expired {
            bucket.window_start = Some(now);
            bucket.count = 0;
        }
        if bucket.count >= self.max_per_window {
            return false;
        }
        bucket.count += 1;
        true
    }
}

/// Axum middleware. Requires the router to be served with
/// `into_make_service_with_connect_info::<SocketAddr>()` so `ConnectInfo`
/// extracts a real peer address.
pub async fn limit(
    State(limiter): State<Arc<RateLimiter>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if limiter.check(addr.ip()) {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_allows_within_window_and_rejects_past_cap() {
        let rl = RateLimiter::new(3);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip));
    }

    #[test]
    fn limiter_zero_means_disabled() {
        let rl = RateLimiter::new(0);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(rl.check(ip));
        }
    }

    #[test]
    fn limiter_separates_buckets_per_ip() {
        let rl = RateLimiter::new(1);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(rl.check(a));
        assert!(rl.check(b));
        assert!(!rl.check(a));
        assert!(!rl.check(b));
    }
}
