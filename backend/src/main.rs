mod api;
mod audit_retention;
mod config;
mod db;
mod db_assets;
mod db_attachments;
mod db_checklists;
mod db_drafts;
mod parser;
mod scheduler_log;
mod severity;
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
    asset_acl::{
        create_handler as create_asset_acl_handler,
        delete_handler as delete_asset_acl_handler,
        list_handler as list_asset_acl_handler,
    },
    asset_groups::{
        add_member_handler as add_asset_group_member_handler,
        create_handler as create_asset_group_handler,
        delete_handler as delete_asset_group_handler,
        list_handler as list_asset_groups_handler,
        list_members_handler as list_asset_group_members_handler,
        remove_member_handler as remove_asset_group_member_handler,
        update_handler as update_asset_group_handler,
    },
    asset_import::import_handler as import_assets_handler,
    assets::{
        compare_handler as compare_assets_handler, create_asset_handler, delete_asset_handler,
        get_asset_handler, list_assets_handler, update_asset_handler,
    },
    attachments::{
        counts_for_checklist_handler as attachments_counts_for_checklist_handler,
        delete_handler as delete_attachment_handler,
        download_handler as download_attachment_handler,
        list_for_rule_handler as list_attachments_for_rule_handler,
        upload_handler as upload_attachment_handler,
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
    bundle::bundle_handler as asset_bundle_handler,
    catalog::{get_catalog, get_health},
    catalog_diff::{
        diff_handler as catalog_diff_handler,
        list_archive_handler as list_catalog_archive_handler,
        seed_archive_handler as seed_catalog_archive_handler,
    },
    compliance_report::{
        download_handler as download_compliance_report_handler,
        list_handler as list_compliance_reports_handler,
        run_report as run_compliance_report,
    },
    checklists::{
        bulk_reapply_handler as bulk_reapply_checklists_handler,
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
    diff::diff_handler,
    drafts::*,
    email::list_deliveries_handler as list_email_deliveries_handler,
    finding_approvals::{
        approve_handler as approve_finding_handler,
        list_handler as list_approvals_handler,
        reject_handler as reject_finding_handler,
        update_policy_handler as update_asset_approval_policy_handler,
    },
    findings::{bulk_handler as bulk_findings_handler, list_handler as list_findings_handler},
    notifications::{
        get_handler as get_notifications_handler,
        mark_read_handler as mark_notifications_read_handler,
    },
    report::report_handler as asset_report_handler,
    rule_bulk_import::bulk_import_handler as rule_bulk_import_handler,
    rule_comments::{
        create_handler as create_rule_comment_handler,
        delete_handler as delete_rule_comment_handler,
        list_handler as list_rule_comments_handler,
        update_handler as update_rule_comment_handler,
    },
    saml::{
        acs_handler as saml_acs_handler,
        login_handler as saml_login_handler,
        metadata_handler as saml_metadata_handler,
        AppSamlState, SamlConfig,
    },
    saved_searches::{
        create_handler as create_saved_search_handler,
        delete_handler as delete_saved_search_handler,
        list_handler as list_saved_searches_handler,
    },
    scheduler_status::list_handler as list_scheduler_runs_handler,
    stig::get_stig,
    stig_validator::lint_handler as stig_lint_handler,
    test_support::{
        backdate_audit_handler, backdate_baseline_handler, backdate_handler, bump_stig_handler,
        reset_handler, run_digest_handler, run_report_handler, run_retention_handler,
        run_scheduler_handler, saml_login_handler as test_saml_login_handler, set_role_handler,
    },
    upload::{upload_library, upload_stig},
    webhooks::{
        create_handler as create_webhook_handler,
        delete_handler as delete_webhook_handler,
        list_deliveries_handler as list_webhook_deliveries_handler,
        list_handler as list_webhooks_handler,
        run_overdue_digest,
        test_handler as test_webhook_handler,
        update_handler as update_webhook_handler,
    },
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

    // SAML SP routes — also public. Built statically from env; if no IdP
    // SSO URL is configured the login route returns 503 with a helpful
    // message but /metadata still works (useful when handing the SP
    // metadata to an IdP admin to register us).
    let saml_config = Arc::new(SamlConfig::from_env(&frontend_origin));
    info!(
        "SAML SP ready (configured={}, sp_entity_id={}, acs_url={})",
        saml_config.is_configured(),
        saml_config.sp_entity_id,
        saml_config.sp_acs_url,
    );
    let saml_state = AppSamlState {
        pool: pool.clone(),
        config: saml_config.clone(),
    };
    let saml_routes: Router = Router::new()
        .route("/auth/saml/login", get(saml_login_handler))
        .route("/auth/saml/acs", post(saml_acs_handler))
        .route("/auth/saml/metadata", get(saml_metadata_handler))
        .with_state(saml_state);

    // Draft + asset + /api/users/me routes — require an authenticated session.
    let draft_routes = Router::new()
        .route("/api/assets", get(list_assets_handler).post(create_asset_handler))
        .route("/api/assets/import", post(import_assets_handler))
        .route(
            "/api/assets/:id",
            get(get_asset_handler)
                .put(update_asset_handler)
                .delete(delete_asset_handler),
        )
        .route(
            "/api/assets/:id/acl",
            get(list_asset_acl_handler).post(create_asset_acl_handler),
        )
        .route(
            "/api/assets/:id/acl/:user_id",
            axum::routing::delete(delete_asset_acl_handler),
        )
        .route(
            "/api/asset-groups",
            get(list_asset_groups_handler).post(create_asset_group_handler),
        )
        .route(
            "/api/asset-groups/:id",
            axum::routing::patch(update_asset_group_handler)
                .delete(delete_asset_group_handler),
        )
        .route(
            "/api/asset-groups/:id/members",
            get(list_asset_group_members_handler).post(add_asset_group_member_handler),
        )
        .route(
            "/api/asset-groups/:id/members/:asset_id",
            axum::routing::delete(remove_asset_group_member_handler),
        )
        .route("/api/assets/:id/report.pdf", get(asset_report_handler))
        .route("/api/assets/:id/bundle.zip", get(asset_bundle_handler))
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
            "/api/checklists/bulk-reapply",
            post(bulk_reapply_checklists_handler),
        )
        .route(
            "/api/checklists/:id/rules/:rule_id",
            axum::routing::patch(update_checklist_rule_handler),
        )
        .route(
            "/api/checklists/:id/rules/bulk-import",
            post(rule_bulk_import_handler),
        )
        .route(
            "/api/checklists/:id/rules/:rule_id/history",
            get(rule_history_handler),
        )
        .route(
            "/api/checklists/:id/rules/:rule_id/attachments",
            get(list_attachments_for_rule_handler)
                .post(upload_attachment_handler),
        )
        .route(
            "/api/checklists/:id/rules/:rule_id/comments",
            get(list_rule_comments_handler).post(create_rule_comment_handler),
        )
        .route(
            "/api/comments/:id",
            axum::routing::patch(update_rule_comment_handler)
                .delete(delete_rule_comment_handler),
        )
        .route(
            "/api/checklists/:id/attachments",
            get(attachments_counts_for_checklist_handler),
        )
        .route(
            "/api/attachments/:id",
            get(download_attachment_handler)
                .delete(delete_attachment_handler),
        )
        .route("/api/activity", get(activity_handler))
        .route("/api/drafts", get(list_drafts_handler).post(create_draft_handler))
        .route("/api/drafts/pending-for-me", get(pending_for_me_handler))
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
        .route("/api/approvals", get(list_approvals_handler))
        .route(
            "/api/approvals/:id/approve",
            post(approve_finding_handler),
        )
        .route(
            "/api/approvals/:id/reject",
            post(reject_finding_handler),
        )
        .route(
            "/api/assets/:id/approval-policy",
            axum::routing::patch(update_asset_approval_policy_handler),
        )
        .route("/api/notifications", get(get_notifications_handler))
        .route(
            "/api/notifications/mark-read",
            post(mark_notifications_read_handler),
        )
        .route("/api/users", get(list_users_handler))
        .route("/api/users/me", get(me_handler))
        .route("/api/dashboard", get(get_dashboard_handler))
        .route("/api/diff", get(diff_handler))
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
        .route("/api/reports", get(list_compliance_reports_handler))
        .route(
            "/api/reports/:id/report.pdf",
            get(download_compliance_report_handler),
        )
        .route("/api/admin/users", get(admin_list_users_handler))
        .route(
            "/api/admin/users/:id/role",
            axum::routing::patch(admin_update_user_role_handler),
        )
        .route(
            "/api/admin/assets/:id/owner",
            axum::routing::patch(admin_update_asset_owner_handler),
        )
        .route(
            "/api/admin/email-deliveries",
            get(list_email_deliveries_handler),
        )
        .route(
            "/api/admin/scheduler-runs",
            get(list_scheduler_runs_handler),
        )
        .route(
            "/api/saved-searches",
            get(list_saved_searches_handler).post(create_saved_search_handler),
        )
        .route(
            "/api/saved-searches/:id",
            axum::routing::delete(delete_saved_search_handler),
        )
        .route(
            "/api/webhooks",
            get(list_webhooks_handler).post(create_webhook_handler),
        )
        .route(
            "/api/webhooks/:id",
            axum::routing::patch(update_webhook_handler)
                .delete(delete_webhook_handler),
        )
        .route(
            "/api/webhooks/:id/deliveries",
            get(list_webhook_deliveries_handler),
        )
        .route("/api/webhooks/:id/test", post(test_webhook_handler))
        .route("/api/stigs/lint", post(stig_lint_handler))
        .route("/api/stigs/:id/diff", get(catalog_diff_handler))
        .route("/api/stigs/:id/archive", get(list_catalog_archive_handler))
        // Viewer-role read-only gate. Sits inside the auth layer so the
        // `AuthUser` extension is populated before it runs (outer layer runs
        // first, so `auth_middleware` is added LAST below).
        .route_layer(middleware::from_fn(api::viewer_guard::viewer_guard))
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
        .merge(saml_routes)
        .merge(draft_routes);

    if std::env::var("STIG_ENV").unwrap_or_default() != "production" {
        let test_router: Router = Router::new()
            .route("/api/test/reset", post(reset_handler))
            .route("/api/test/set-role", post(set_role_handler))
            .route("/api/test/snapshot", post(snapshot_trigger_handler))
            .route("/api/test/backdate-rule", post(backdate_handler))
            .route("/api/test/backdate-baseline", post(backdate_baseline_handler))
            .route("/api/test/bump-stig", post(bump_stig_handler))
            .route("/api/test/run-digest", post(run_digest_handler))
            .route("/api/test/run-report", post(run_report_handler))
            .route("/api/test/run-retention", post(run_retention_handler))
            .route("/api/test/backdate-audit", post(backdate_audit_handler))
            .route("/api/test/run-scheduler", post(run_scheduler_handler))
            .route("/api/test/saml-login", post(test_saml_login_handler))
            .route("/api/test/seed-archive", post(seed_catalog_archive_handler))
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
                let result = scheduler_log::record(&db, "sync", || async {
                    sync::run_sync(&cfg, &src, &db).await?;
                    Ok::<String, anyhow::Error>(format!("synced {} source(s)", src.len()))
                })
                .await;
                if let Err(e) = result {
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
                let result = scheduler_log::record(&db, "snapshot", || async {
                    let n = take_snapshot(&db)
                        .await
                        .map_err(anyhow::Error::from)?;
                    Ok::<String, anyhow::Error>(format!("captured {n} checklists"))
                })
                .await;
                match result {
                    Ok(msg) => tracing::info!("dashboard snapshot: {msg}"),
                    Err(e) => tracing::error!("dashboard snapshot failed: {e:#}"),
                }
            }
        });
    }

    // Overdue-digest scheduler — fan a fleet-wide overdue summary out to
    // any webhook subscribed to `overdue_digest`. The 23-hour cooldown
    // lives inside `run_overdue_digest`, so the loop is safe to tick a
    // little under 24h without spamming.
    {
        let digest_hours: u64 = std::env::var("OVERDUE_DIGEST_INTERVAL_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);
        let db = pool.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(digest_hours * 3600));
            loop {
                interval.tick().await;
                let result = scheduler_log::record(&db, "overdue_digest", || async {
                    let n = run_overdue_digest(&db).await?;
                    Ok::<String, anyhow::Error>(format!("attempted {n} webhook(s)"))
                })
                .await;
                match result {
                    Ok(msg) => tracing::info!("overdue digest: {msg}"),
                    Err(e) => tracing::error!("overdue digest sweep failed: {e:#}"),
                }
            }
        });
    }

    // Audit-retention scheduler — prunes `rule_audit` rows older than
    // `AUDIT_RETENTION_DAYS` and (optionally) archives them as JSONL
    // under `${data_dir}/audit_archive/`. Mirrors the other long-loop
    // schedulers — interval is in hours so it lines up with the rest.
    {
        let retention_hours: u64 = std::env::var("AUDIT_RETENTION_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);
        let retain_days: i64 = std::env::var("AUDIT_RETENTION_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(365);
        let archive_enabled: bool = std::env::var("AUDIT_ARCHIVE_ENABLED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true);
        let db = pool.clone();
        let cfg = config.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(retention_hours * 3600));
            loop {
                interval.tick().await;
                let result = scheduler_log::record(&db, "audit_retention", || async {
                    let n = audit_retention::run_prune(
                        &db,
                        &cfg.data_dir,
                        retain_days,
                        archive_enabled,
                    )
                    .await?;
                    Ok::<String, anyhow::Error>(format!(
                        "pruned {n} rows (retain_days={retain_days}, archive={archive_enabled})"
                    ))
                })
                .await;
                match result {
                    Ok(msg) => tracing::info!("audit retention: {msg}"),
                    Err(e) => tracing::error!("audit retention failed: {e:#}"),
                }
            }
        });
    }

    // Continuous compliance report scheduler — renders a fleet-wide PDF
    // on a configurable cadence (default weekly) and fires a
    // `compliance_report` webhook event so Slack / receivers can pick up
    // the link.
    {
        let report_hours: u64 = std::env::var("COMPLIANCE_REPORT_INTERVAL_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(168);
        let range_days: i32 = std::env::var("COMPLIANCE_REPORT_RANGE_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let db = pool.clone();
        let cfg = config.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(report_hours * 3600));
            loop {
                interval.tick().await;
                let result = scheduler_log::record(&db, "compliance_report", || async {
                    let row = run_compliance_report(&db, &cfg.data_dir, range_days).await?;
                    Ok::<String, anyhow::Error>(format!(
                        "generated id={} pdf={}",
                        row.id, row.pdf_path
                    ))
                })
                .await;
                match result {
                    Ok(msg) => tracing::info!("compliance report: {msg}"),
                    Err(e) => tracing::error!("compliance report failed: {e:#}"),
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
