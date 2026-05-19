mod api;
mod config;
mod db;
mod db_assets;
mod db_drafts;
mod parser;
mod sync;

use anyhow::Result;
use axum::{extract::DefaultBodyLimit, middleware, routing::{get, post}, Router};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower_http::cors::CorsLayer;
use axum::http::{header, HeaderValue, Method};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::{
    assets::{
        create_asset_handler, delete_asset_handler, get_asset_handler, list_assets_handler,
        update_asset_handler,
    },
    auth::{
        auth_middleware, build_oidc_context, callback_handler, login_handler, logout_handler,
        me_handler, AppAuthState, OidcEnv,
    },
    catalog::{get_catalog, get_health},
    drafts::*,
    stig::get_stig,
    test_support::{reset_handler, set_role_handler},
    upload::{upload_library, upload_stig},
};
use config::{load_sources, Config};
use db::init_pool;

#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<PgPool>,
    pub config: Arc<Config>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            "stig_viewer_backend=info,tower_http=info".into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

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

    // ── OIDC setup ──────────────────────────────────────────────────────────
    let oidc_env = OidcEnv::from_env()?;
    let frontend_origin = oidc_env.frontend_url.clone();
    let oidc = build_oidc_context(&oidc_env).await?;
    info!(
        "OIDC client ready (issuer={}, test_header_auth={})",
        oidc_env.internal_issuer_url, oidc_env.allow_test_auth_header
    );

    let auth_state = AppAuthState {
        pool: pool.clone(),
        oidc: oidc.clone(),
    };

    // CORS — cookie-based auth requires a specific origin (not "*")
    // plus `allow_credentials`. Allow the frontend origin from FRONTEND_URL.
    let cors = CorsLayer::new()
        .allow_origin(frontend_origin.parse::<HeaderValue>()?)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::COOKIE, header::HeaderName::from_static("x-user-id")])
        .allow_credentials(true);

    let state = AppState {
        pool: pool.clone(),
        config: config.clone(),
    };

    // Auth flow routes — public, do not require an existing session.
    let auth_routes: Router = Router::new()
        .route("/auth/login", get(login_handler))
        .route("/auth/callback", get(callback_handler))
        .route("/auth/logout", post(logout_handler))
        .with_state(auth_state.clone());

    // Draft + asset + /api/users/me routes — require an authenticated session.
    let draft_routes = Router::new()
        .route("/api/assets", get(list_assets_handler).post(create_asset_handler))
        .route(
            "/api/assets/:id",
            get(get_asset_handler)
                .put(update_asset_handler)
                .delete(delete_asset_handler),
        )
        .route("/api/drafts", get(list_drafts_handler).post(create_draft_handler))
        .route("/api/drafts/from-stig/:stig_id", post(fork_from_stig_handler))
        .route(
            "/api/drafts/:id",
            get(get_draft_handler)
                .put(update_draft_handler)
                .delete(delete_draft_handler),
        )
        .route("/api/drafts/:id/next-vuln-id", post(next_vuln_id_handler))
        .route("/api/drafts/:id/submit", post(submit_handler))
        .route("/api/drafts/:id/review", post(review_handler))
        .route("/api/drafts/:id/approve", post(approve_handler))
        .route("/api/drafts/:id/reject", post(reject_handler))
        .route("/api/drafts/:id/revise", post(revise_handler))
        .route(
            "/api/drafts/:id/comments",
            get(list_comments_handler).post(add_comment_handler),
        )
        .route("/api/users/me", get(me_handler))
        .route_layer(middleware::from_fn_with_state(
            auth_state.clone(),
            auth_middleware,
        ))
        .with_state(state.clone());

    let mut app = Router::new()
        .route("/api/health", get(get_health))
        .route("/api/catalog", get(get_catalog))
        .route("/api/stigs/:id", get(get_stig))
        .route("/api/upload", post(upload_stig))
        .route("/api/upload/library", post(upload_library))
        .with_state(state.clone())
        .merge(auth_routes)
        .merge(draft_routes);

    if std::env::var("STIG_ENV").unwrap_or_default() != "production" {
        let test_router: Router = Router::new()
            .route("/api/test/reset", post(reset_handler))
            .route("/api/test/set-role", post(set_role_handler))
            .with_state(state.clone());
        app = app.merge(test_router);
    }

    let app = app
        .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
        .layer(cors);

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
