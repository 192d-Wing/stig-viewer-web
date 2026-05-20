mod api;
mod config;
mod db;
mod db_assets;
mod db_checklists;
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
    admin::{
        list_users_handler as admin_list_users_handler,
        update_asset_owner_handler as admin_update_asset_owner_handler,
        update_user_role_handler as admin_update_user_role_handler,
    },
    assets::{
        compare_handler as compare_assets_handler, create_asset_handler, delete_asset_handler,
        get_asset_handler, list_assets_handler, update_asset_handler,
    },
    audit::{activity_handler, rule_history_handler},
    auth::{
        auth_middleware, build_oidc_context, callback_handler, list_users_handler, login_handler,
        logout_handler, me_handler, AppAuthState, OidcEnv,
    },
    baselines::{
        create_handler as create_baseline_handler,
        delete_handler as delete_baseline_handler,
        diff_handler as baseline_diff_handler,
        list_handler as list_baselines_handler,
    },
    catalog::{get_catalog, get_health},
    checklists::{
        create_handler as create_checklist_handler,
        delete_handler as delete_checklist_handler,
        get_handler as get_checklist_handler,
        list_for_asset_handler as list_checklists_for_asset_handler,
        reapply_handler as reapply_checklist_handler,
        update_rule_handler as update_checklist_rule_handler,
    },
    dashboard::{
        asset_trend_handler,
        get_handler as get_dashboard_handler,
        snapshot_handler as snapshot_trigger_handler,
        take_snapshot,
        trend_handler as get_dashboard_trend_handler,
    },
    drafts::*,
    findings::{bulk_handler as bulk_findings_handler, list_handler as list_findings_handler},
    notifications::{
        get_handler as get_notifications_handler,
        mark_read_handler as mark_notifications_read_handler,
    },
    report::report_handler as asset_report_handler,
    stig::get_stig,
    test_support::{backdate_handler, bump_stig_handler, reset_handler, set_role_handler},
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
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
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
        .route("/api/assets/:id/report.pdf", get(asset_report_handler))
        .route("/api/assets/:id/trend", get(asset_trend_handler))
        .route(
            "/api/assets/:left/diff/:right",
            get(compare_assets_handler),
        )
        .route(
            "/api/assets/:id/checklists",
            get(list_checklists_for_asset_handler).post(create_checklist_handler),
        )
        .route(
            "/api/checklists/:id",
            get(get_checklist_handler).delete(delete_checklist_handler),
        )
        .route(
            "/api/checklists/:id/reapply",
            post(reapply_checklist_handler),
        )
        .route(
            "/api/checklists/:id/rules/:rule_id",
            axum::routing::patch(update_checklist_rule_handler),
        )
        .route(
            "/api/checklists/:id/rules/:rule_id/history",
            get(rule_history_handler),
        )
        .route("/api/activity", get(activity_handler))
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
        .route("/api/notifications", get(get_notifications_handler))
        .route(
            "/api/notifications/mark-read",
            post(mark_notifications_read_handler),
        )
        .route("/api/users", get(list_users_handler))
        .route("/api/users/me", get(me_handler))
        .route("/api/dashboard", get(get_dashboard_handler))
        .route("/api/dashboard/trend", get(get_dashboard_trend_handler))
        .route("/api/findings", get(list_findings_handler))
        .route(
            "/api/findings/bulk",
            axum::routing::patch(bulk_findings_handler),
        )
        .route(
            "/api/baselines",
            get(list_baselines_handler).post(create_baseline_handler),
        )
        .route("/api/baselines/:id", axum::routing::delete(delete_baseline_handler))
        .route("/api/baselines/:id/diff", get(baseline_diff_handler))
        .route("/api/admin/users", get(admin_list_users_handler))
        .route(
            "/api/admin/users/:id/role",
            axum::routing::patch(admin_update_user_role_handler),
        )
        .route(
            "/api/admin/assets/:id/owner",
            axum::routing::patch(admin_update_asset_owner_handler),
        )
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
            .route("/api/test/snapshot", post(snapshot_trigger_handler))
            .route("/api/test/backdate-rule", post(backdate_handler))
            .route("/api/test/bump-stig", post(bump_stig_handler))
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

    // Dashboard snapshot scheduler — captures one row per checklist into
    // checklist_snapshots on each tick. Interval is in hours so it lines
    // up with the existing scheduler pattern; default 24h.
    {
        let snap_hours: u64 = std::env::var("DASHBOARD_SNAPSHOT_INTERVAL_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);
        let db = pool.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(snap_hours * 3600));
            loop {
                interval.tick().await;
                match take_snapshot(&db).await {
                    Ok(n) => tracing::info!("dashboard snapshot captured: {n} checklists"),
                    Err(e) => tracing::error!("dashboard snapshot failed: {e:#}"),
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
