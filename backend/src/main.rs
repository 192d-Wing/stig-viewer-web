mod api;
mod config;
mod db;
mod parser;
mod sync;

use anyhow::Result;
use axum::{extract::DefaultBodyLimit, routing::{get, post}, Router};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::{catalog::{get_catalog, get_health}, stig::get_stig, upload::{upload_library, upload_stig}};
use config::{load_sources, Config};
use db::init_pool;

/// Unified application state shared by all Axum handlers.
/// Axum requires a single State type per router.
#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<PgPool>,
    pub config: Arc<Config>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise structured logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "stig_viewer_backend=info,tower_http=info".into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Arc::new(Config::from_env()?);
    let sources = Arc::new(load_sources()?);

    info!(
        "Loaded {} STIG sources, data_dir={}",
        sources.len(),
        config.data_dir.display()
    );

    // Ensure data directory exists
    tokio::fs::create_dir_all(config.data_dir.join("stigs")).await?;

    // Connect to Postgres and run migrations
    let pool = Arc::new(init_pool(&config.database_url).await?);
    info!("Database connected and migrations applied");

    // CORS — allow all origins in dev; tighten in production via env or nginx
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let state = AppState {
        pool: pool.clone(),
        config: config.clone(),
    };

    // Build Axum router — single AppState shared by all handlers
    //
    // Body limit applied globally at the router level (outermost layer) so it
    // takes effect before Axum's built-in 2 MB default.  500 MB covers the
    // largest DISA library bundle; all other routes are well under this.
    let app = Router::new()
        .route("/api/health", get(get_health))
        .route("/api/catalog", get(get_catalog))
        .route("/api/stigs/:id", get(get_stig))
        .route("/api/upload", post(upload_stig))
        .route("/api/upload/library", post(upload_library))
        .with_state(state)
        .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        .layer(cors);

    // ── Scheduler ────────────────────────────────────────────────────────────
    {
        let cfg = config.clone();
        let src = sources.clone();
        let db = pool.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(cfg.sync_interval_hours * 3600));
            loop {
                interval.tick().await; // first tick is immediate
                if let Err(e) = sync::run_sync(&cfg, &src, &db).await {
                    tracing::error!("Sync error: {e:#}");
                }
            }
        });
    }

    // ── Start server ─────────────────────────────────────────────────────────
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on http://{addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install Ctrl+C handler");
    info!("Shutting down…");
}
