//! Prometheus `/metrics` endpoint + the HTTP-metrics middleware.
//!
//! Metrics recorded today:
//!   http_requests_total{method,path,status}    — per-request counter
//!   http_request_duration_seconds{method,path} — histogram
//!   uploads_total{action}                      — upload.stig, upload.library
//!   audit_events_total{action}                 — any audit.log() write
//!
//! The recorder is installed once at startup by `install_recorder`. When it
//! isn't installed (tests, dev without ops env), all `metrics::*` macro calls
//! are no-ops so handlers don't have to branch.

use axum::{
    extract::{MatchedPath, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

use crate::AppState;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus recorder. Safe to call more than once —
/// subsequent calls are no-ops. Returns `true` the first time it actually
/// installs so the caller can log.
pub fn install_recorder() -> bool {
    if HANDLE.get().is_some() {
        return false;
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("prometheus recorder install");
    HANDLE.set(handle).is_ok()
}

/// `GET /metrics` — returns the current Prometheus text exposition format.
/// Returns 503 when the recorder hasn't been installed (ops disabled).
pub async fn scrape(State(_state): State<AppState>) -> Result<String, StatusCode> {
    match HANDLE.get() {
        Some(h) => Ok(h.render()),
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Middleware that measures per-request count + latency. Path is the Axum
/// matched path (e.g. `/api/stigs/:id`) rather than the raw URL, so the
/// cardinality stays bounded.
pub async fn track(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().as_str().to_owned();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();

    metrics::counter!(
        "http_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status,
    )
    .increment(1);
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method,
        "path" => path,
    )
    .record(start.elapsed().as_secs_f64());

    res
}

/// Convenience for handlers / audit helpers that want to bump a named counter.
pub fn record_event(family: &'static str, action: &str) {
    metrics::counter!(family, "action" => action.to_string()).increment(1);
}
