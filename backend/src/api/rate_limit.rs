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
/// `/api/test/*` is gated by `STIG_ENV != "production"` at registration
/// time, so this only matters in dev / CI — but it's important there: the
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
