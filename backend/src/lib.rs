//! Library crate counterpart to the `stig-viewer-backend` binary.
//!
//! The `run()` function is what `src/main.rs` calls; `build_app` and
//! `AppState` are also exported so integration tests in `tests/` can
//! construct and drive the HTTP router against a test database.

pub mod api;
pub mod audit;
pub mod auth;
pub mod config;
pub mod db;
pub mod parser;
pub mod sync;

use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, FromRef},
    middleware,
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::Key;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::{
    audit::list_audit,
    catalog::{get_catalog, get_health},
    metrics::{scrape as metrics_scrape, track as metrics_track},
    ops::{livez, readyz, trigger_sync},
    request_id::with_request_id,
    stig::get_stig,
    upload::{upload_library, upload_stig},
    workspaces,
};
use auth::AuthState;
use config::{load_sources, Config, StigSource};
use db::init_pool;

/// Unified application state shared by all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<PgPool>,
    pub config: Arc<Config>,
    /// `Some` when OIDC is configured; `None` enables dev open mode.
    pub auth: Option<AuthState>,
    /// DISA sources manifest. `None` when tests skip loading it; the
    /// `POST /api/sync` endpoint returns an error in that case.
    pub sources: Option<Arc<Vec<StigSource>>>,
}

// Required so PrivateCookieJar can pull the cookie Key out of AppState.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state
            .auth
            .as_ref()
            .map(|a| a.cookie_key.clone())
            // Dummy key used only when auth is disabled and no cookies are
            // ever actually read or written; the extractor bails out early.
            .unwrap_or_else(|| Key::from(&[0u8; 64]))
    }
}

/// Assemble the Axum router from the supplied state.
///
/// Kept separate from `run()` so integration tests can build the same
/// router and drive it directly.
pub fn build_app(state: AppState) -> Router {
    // CORS: credentialed requests require a specific origin allowlist.
    let allowed_origins: Vec<_> = std::env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:5173,http://localhost:8080".into())
        .split(',')
        .filter_map(|s| s.trim().parse::<axum::http::HeaderValue>().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_credentials(true)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT]);

    // Per-IP rate limiter applied to upload routes only.
    let upload_limiter = Arc::new(api::ratelimit::RateLimiter::new(
        state.config.upload_rate_per_min,
    ));

    let public = Router::new()
        // /api/health is retained as an alias for /api/readyz so existing
        // probes keep working; prefer /api/livez or /api/readyz for new ones.
        .route("/api/health", get(get_health))
        .route("/api/livez", get(livez))
        .route("/api/readyz", get(readyz))
        .route("/metrics", get(metrics_scrape))
        .merge(auth::routes());

    let protected_reads = Router::new()
        .route("/api/catalog", get(get_catalog))
        .route("/api/stigs/:id", get(get_stig))
        .route("/api/audit", get(list_audit))
        .route(
            "/api/workspaces/:stig_id",
            get(workspaces::get).put(workspaces::put),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::extractor::require_auth,
        ));

    // Admin-only mutations that aren't uploads.
    let protected_admin =
        Router::new()
            .route("/api/sync", post(trigger_sync))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth::extractor::require_auth,
            ));

    let protected_uploads = Router::new()
        .route("/api/upload", post(upload_stig))
        .route("/api/upload/library", post(upload_library))
        .layer(middleware::from_fn_with_state(
            upload_limiter.clone(),
            api::ratelimit::limit,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::extractor::require_auth,
        ));

    Router::new()
        .merge(public)
        .merge(protected_reads)
        .merge(protected_admin)
        .merge(protected_uploads)
        .with_state(state)
        .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        .layer(cors)
        // These two run outside the per-route handlers: metrics sees every
        // request (so we can diff served vs. 4xx); request_id wraps the whole
        // thing in a tracing span so handler logs carry the id.
        .layer(middleware::from_fn(metrics_track))
        .layer(middleware::from_fn(with_request_id))
}

/// Full server bootstrap — loads config, connects to Postgres, runs the
/// DISA sync scheduler, and serves the app on `config.port`.
pub async fn run() -> Result<()> {
    init_tracing();

    // Install the Prometheus recorder before any metrics calls fire. Macros
    // are no-ops before this so ordering is tolerant, but in-order is clean.
    if api::metrics::install_recorder() {
        tracing::info!("Prometheus /metrics recorder installed");
    }

    let config = Arc::new(Config::from_env()?);
    let sources = Arc::new(load_sources()?);

    info!(
        "Loaded {} STIG sources, data_dir={}",
        sources.len(),
        config.data_dir.display()
    );

    tokio::fs::create_dir_all(config.data_dir.join("stigs")).await?;

    let pool = Arc::new(init_pool(&config.database_url).await?);
    info!("Database connected and migrations applied");

    let auth = AuthState::try_from_env(&config).await?;
    match &auth {
        Some(a) => info!(
            "OIDC enabled: issuer={}",
            a.config.issuer_url.as_deref().unwrap_or("?")
        ),
        None => {
            if std::env::var("REQUIRE_AUTH")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                anyhow::bail!(
                    "REQUIRE_AUTH is set but OIDC env vars are incomplete. See .env.example."
                );
            }
            warn!(
                "OIDC not configured; starting in DEV OPEN MODE — all /api routes are unauthenticated. \
                 Set OIDC_* env vars (and REQUIRE_AUTH=1 in production) to enforce login."
            );
        }
    }

    let state = AppState {
        pool: pool.clone(),
        config: config.clone(),
        auth,
        sources: Some(sources.clone()),
    };

    let app = build_app(state);

    // Scheduler.
    {
        let cfg = config.clone();
        let src = sources.clone();
        let db = pool.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(cfg.sync_interval_hours * 3600));
            loop {
                interval.tick().await;
                if let Err(e) = sync::run_sync(&cfg, &src, &db).await {
                    tracing::error!("Sync error: {e:#}");
                }
            }
        });
    }

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    info!("Listening on http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

/// Initialise tracing. `LOG_FORMAT=json` emits structured JSON lines (one
/// per event) which is what most log aggregators want; anything else uses
/// the human-friendly default formatter.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "stig_viewer_backend=info,tower_http=info".into());

    let json = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}

/// Wait for Ctrl+C (local dev) or SIGTERM (container orchestrators). On
/// non-Unix platforms only Ctrl+C is installed.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Shutting down (SIGINT)…"),
        _ = terminate => info!("Shutting down (SIGTERM)…"),
    }
}
