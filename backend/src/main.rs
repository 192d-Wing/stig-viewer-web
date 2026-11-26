#[cfg(all(feature = "fips", feature = "non-fips"))]
compile_error!(
    "features `fips` and `non-fips` are mutually exclusive; build the FIPS binary with `--no-default-features --features fips`"
);
#[cfg(not(any(feature = "fips", feature = "non-fips")))]
compile_error!("enable exactly one of the `non-fips` (default) or `fips` features");

mod api;
mod audit_retention;
mod config;
mod crypto;
mod db;
mod db_assets;
mod db_attachments;
mod db_audit;
mod db_checklist_sets;
mod db_checklists;
mod db_drafts;
mod db_notice;
mod db_roles;
mod db_saml_replay;
mod detached;
mod failure_counters;
mod fips;
mod integrity;
mod parser;
mod pdf;
mod scheduler_log;
mod seed;
mod severity;
mod signers;
mod stig_id;
mod sync;
#[cfg(test)]
mod test_fixtures;
mod zip_safe;

use anyhow::{Context as _, Result};
use axum::http::{header, HeaderValue, Method};
use axum::{
    extract::DefaultBodyLimit,
    handler::Handler,
    middleware,
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::{
    fmt::writer::BoxMakeWriter, layer::SubscriberExt, util::SubscriberInitExt,
};

use api::{
    abac::{
        create_handler as create_abac_policy_handler, delete_handler as delete_abac_policy_handler,
        list_handler as list_abac_policies_handler, update_handler as update_abac_policy_handler,
    },
    admin::{
        list_users_handler as admin_list_users_handler,
        update_asset_owner_handler as admin_update_asset_owner_handler,
        update_user_role_handler as admin_update_user_role_handler,
    },
    asset_acl::{
        create_handler as create_asset_acl_handler, delete_handler as delete_asset_acl_handler,
        list_handler as list_asset_acl_handler,
    },
    asset_email_cc::{
        create_handler as create_asset_email_cc_handler,
        delete_handler as delete_asset_email_cc_handler,
        list_handler as list_asset_email_cc_handler, run_asset_email_schedules,
        send_handler as send_asset_email_report_handler,
    },
    asset_groups::{
        add_member_handler as add_asset_group_member_handler,
        create_handler as create_asset_group_handler, delete_handler as delete_asset_group_handler,
        list_handler as list_asset_groups_handler,
        list_members_handler as list_asset_group_members_handler,
        remove_member_handler as remove_asset_group_member_handler,
        update_handler as update_asset_group_handler,
    },
    asset_import::import_handler as import_assets_handler,
    assets::{
        compare_handler as compare_assets_handler, create_asset_handler, delete_asset_handler,
        get_asset_handler, list_assets_handler, patch_asset_handler, update_asset_handler,
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
    backup::{
        download_handler as admin_backup_download_handler, restore_handler as admin_restore_handler,
    },
    baselines::{
        create_handler as create_baseline_handler, delete_handler as delete_baseline_handler,
        diff_handler as baseline_diff_handler, list_handler as list_baselines_handler,
    },
    bundle::bundle_handler as asset_bundle_handler,
    catalog::get_catalog,
    catalog_diff::{
        diff_handler as catalog_diff_handler, list_archive_handler as list_catalog_archive_handler,
    },
    catalog_search::search_handler as catalog_search_handler,
    checklist_save::save_handler as checklist_save_handler,
    checklist_sets::{
        add_stig_handler as add_checklist_set_stig_handler,
        autosave_handler as autosave_checklist_set_handler,
        create_handler as create_checklist_set_handler,
        delete_handler as delete_checklist_set_handler, get_handler as get_checklist_set_handler,
        list_handler as list_checklist_sets_handler, patch_handler as patch_checklist_set_handler,
        remove_stig_handler as remove_checklist_set_stig_handler,
        save_to_system_handler as save_checklist_set_to_system_handler,
    },
    checklists::{
        bulk_reapply_handler as bulk_reapply_checklists_handler,
        create_handler as create_checklist_handler, delete_handler as delete_checklist_handler,
        get_handler as get_checklist_handler,
        list_for_asset_handler as list_checklists_for_asset_handler,
        reapply_handler as reapply_checklist_handler,
        update_rule_handler as update_checklist_rule_handler,
    },
    compliance_report::{
        download_handler as download_compliance_report_handler,
        list_handler as list_compliance_reports_handler, run_report as run_compliance_report,
    },
    dashboard::{
        asset_trend_handler, get_handler as get_dashboard_handler, take_snapshot,
        trend_handler as get_dashboard_trend_handler,
    },
    diff::diff_handler,
    drafts::*,
    email::list_deliveries_handler as list_email_deliveries_handler,
    finding_approvals::{
        approve_handler as approve_finding_handler, list_handler as list_approvals_handler,
        reject_handler as reject_finding_handler,
        update_policy_handler as update_asset_approval_policy_handler,
    },
    findings::list_handler as list_findings_handler,
    findings_bulk::bulk_handler as bulk_findings_handler,
    health::{failure_counters_handler, get_health},
    notifications::{
        get_handler as get_notifications_handler,
        get_prefs_handler as get_notification_prefs_handler,
        mark_read_handler as mark_notifications_read_handler,
        put_prefs_handler as put_notification_prefs_handler,
    },
    oscal::export_handler as asset_oscal_handler,
    report::report_handler as asset_report_handler,
    rule_bulk_import::bulk_import_handler as rule_bulk_import_handler,
    rule_bulk_status::bulk_status_handler as rule_bulk_status_handler,
    rule_comments::{
        add_reaction_handler as add_comment_reaction_handler,
        create_handler as create_rule_comment_handler,
        delete_handler as delete_rule_comment_handler, list_handler as list_rule_comments_handler,
        remove_reaction_handler as remove_comment_reaction_handler,
        update_handler as update_rule_comment_handler,
    },
    saml::{
        acs_handler as saml_acs_handler, login_handler as saml_login_handler,
        metadata_handler as saml_metadata_handler, AppSamlState, SamlConfig,
    },
    saved_searches::{
        create_handler as create_saved_search_handler,
        delete_handler as delete_saved_search_handler, list_handler as list_saved_searches_handler,
    },
    scheduler_status::list_handler as list_scheduler_runs_handler,
    sessions::{
        list_handler as list_active_sessions_handler, revoke_handler as revoke_session_handler,
    },
    stig::get_stig,
    stig_validator::lint_handler as stig_lint_handler,
    upload::{upload_library, upload_stig, MAX_UPLOAD_BYTES},
    webhooks::{
        create_handler as create_webhook_handler, delete_handler as delete_webhook_handler,
        list_deliveries_handler as list_webhook_deliveries_handler,
        list_handler as list_webhooks_handler, run_overdue_digest,
        test_handler as test_webhook_handler, update_handler as update_webhook_handler,
        verify_recipe_handler as webhook_verify_recipe_handler,
    },
};
use config::{load_sources, Config, TestHooks};
use db::{connect_pool, run_migrations};

/// Request-body cap for every route that doesn't set its own. Covers JSON
/// payloads, CSV imports and STIG JSON lint uploads.
const DEFAULT_BODY_LIMIT: usize = 10 * 1024 * 1024;
/// Evidence attachments: the handler enforces 25 MiB of file data; leave
/// headroom for multipart framing.
const ATTACHMENT_BODY_LIMIT: usize = 26 * 1024 * 1024;
/// Bulk status change: up to 2000 rule ids plus one finding-details text
/// capped at 32 KiB by the handler; 256 KiB covers that with headroom.
const BULK_STATUS_BODY_LIMIT: usize = 256 * 1024;
/// "Save to system": a whole STIG's worth of per-rule status, finding details
/// and comments. Each text field is capped at 32 KiB by the handler, but a
/// real checklist averages a few KiB per rule across 300-1000 rules, so 4 MiB
/// fits any realistic STIG while keeping the worst-case write fan-out small.
const SAVE_TO_SYSTEM_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// Checklist-set autosave: up to 2000 rule changes with capped text fields.
const CHECKLIST_SET_AUTOSAVE_BODY_LIMIT: usize = 1024 * 1024;

/// The other mutating checklist-set routes carry only a name, ids and a revision.
const CHECKLIST_SET_SMALL_BODY_LIMIT: usize = 16 * 1024;
/// `/api/sign` takes base64 JSON of up to 100 MiB of content (the handler
/// enforces the decoded size); base64 inflates that by 4/3.
const SIGN_BODY_LIMIT: usize = 140 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub pool: Arc<PgPool>,
    pub config: Arc<Config>,
    /// `Some` when `SIGNING_KEY_HEX` is configured. Both `/api/sign` and
    /// `/api/signing/pubkey` return 503 when this is `None`.
    pub signing: Option<api::signing::SigningState>,
    /// Detached request work (change plus its audit event); awaited at
    /// shutdown. See [`detached`].
    pub tasks: Arc<detached::Tracker>,
    /// Cap on in-flight audited requests; see [`api::admission`].
    pub admission: Arc<api::admission::Admission>,
}

/// Connect the application pool and make sure the schema is current.
/// With `DATABASE_MIGRATION_URL` the owner role migrates first; otherwise a
/// role that owns the schema migrates itself (legacy single-role setup, for
/// development only) and any other role only verifies that migrations were
/// applied externally.
async fn connect_database(config: &Config, hooks: &TestHooks) -> Result<PgPool> {
    let has_owner_url = config.database_migration_url.is_some();
    if let Some(owner_url) = config.database_migration_url.as_deref() {
        db_roles::migrate_as_owner(
            owner_url,
            &config.database_url,
            &owner_step(hooks, "server_startup"),
        )
        .await?;
    }
    let pool = connect_pool(&config.database_url).await?;
    let can_migrate = !has_owner_url && db_roles::can_migrate(&pool).await?;
    match db_roles::startup_path(has_owner_url, || can_migrate) {
        db_roles::StartupPath::OwnerMigrates => {
            db_roles::verify_or_record_refusal(&pool, hooks.production).await?;
            info!("Database connected; migrations applied by the owner role");
        }
        db_roles::StartupPath::SelfMigrate => {
            let step = owner_step(hooks, "server_self_migrate");
            let before = db_roles::applied_versions(&mut *pool.acquire().await?).await?;
            run_migrations(&pool).await?;
            db_roles::finish_self_migrate(&pool, &step, &before).await?;
            info!("Database connected and migrations applied");
        }
        db_roles::StartupPath::VerifyOnly => {
            db_roles::verify_or_record_refusal(&pool, hooks.production).await?;
            info!("Database connected; migrations verified (applied externally)");
        }
    }
    Ok(pool)
}

/// The owner step's inputs from the environment: the retention floor is
/// `AUDIT_RETENTION_DAYS` as seen by this process.
fn owner_step(hooks: &TestHooks, source: &'static str) -> db_roles::OwnerStep {
    db_roles::OwnerStep {
        test_routes: hooks.enable_test_routes,
        production: hooks.production,
        retention_floor_days: audit_retention::retain_days_from_env(),
        source,
    }
}

/// Log a loud warning for each test-only hook that is switched on.
fn warn_enabled_test_hooks(test_hooks: &TestHooks) {
    if test_hooks.enable_test_routes {
        tracing::warn!(
            "STIG_ENABLE_TEST_ROUTES is on: unauthenticated /api/test/* routes are mounted \
             (they can reset data and write synthetic system audit records). \
             Never enable this on a reachable deployment."
        );
    }
    if test_hooks.allow_test_auth_header {
        tracing::warn!(
            "ALLOW_TEST_AUTH_HEADER is on: any client can authenticate as any user via \
             X-User-Id. Never enable this on a reachable deployment."
        );
    }
}

/// Connect (migrating as the owner if configured), apply the audit test-mode
/// policy, and enforce the owner/app role boundary before anything is served.
async fn open_database(config: &Config, test_hooks: &TestHooks) -> Result<sqlx::PgPool> {
    if let Some(w) = db_roles::owner_url_on_server_warning(
        test_hooks.production,
        config.database_migration_url.is_some(),
    ) {
        tracing::warn!("{w}");
    }
    let pool = connect_database(config, test_hooks).await?;
    if test_hooks.production && config.database_migration_url.is_some() {
        db_roles::record_owner_url_on_server(&pool, test_hooks.enable_test_routes).await;
    }
    if let Err(e) =
        db_audit::apply_test_maintenance_policy(&pool, test_hooks.enable_test_routes).await
    {
        db_roles::record_boundary_refusal(&pool, "test_mode_policy", test_hooks.production).await;
        return Err(e);
    }
    let violations = match db_roles::boundary_violations(&pool, test_hooks.enable_test_routes).await
    {
        Ok(v) => v,
        Err(e) => {
            db_roles::record_boundary_refusal(&pool, "check_failed", test_hooks.production).await;
            return Err(e);
        }
    };
    db_roles::enforce_boundary(
        &pool,
        test_hooks.production,
        test_hooks.enable_test_routes,
        &violations,
    )
    .await?;
    Ok(pool)
}

/// The `migrate` subcommand: validate the test hooks, run migrations and the
/// application-role grants as the owner role, then return.
async fn run_migrate_command() -> Result<()> {
    let hooks = TestHooks::from_env();
    let config = Config::from_env()?;
    let owner_url =
        match db_roles::migrate_preconditions(&hooks, config.database_migration_url.as_deref()) {
            Ok(u) => u,
            Err(e) => {
                // No connection exists yet, so the log line is the record.
                tracing::error!(
                    target: "audit",
                    action = "db.migrate",
                    outcome = "failure",
                    source = "migrate_command",
                    stage = "preconditions",
                    "migrate preconditions failed (no audit row written)"
                );
                return Err(e);
            }
        };
    db_roles::migrate_as_owner(
        owner_url,
        &config.database_url,
        &owner_step(&hooks, "migrate_command"),
    )
    .await?;
    info!("Migrations applied and application role grants updated");
    Ok(())
}

/// The `gen-mldsa-key` subcommand: generate an ML-DSA-87 key and print it as
/// base64 PKCS#8 on stdout (the value for `SIGNING_MLDSA87_KEY_B64`) and its
/// key id on stderr. Nothing is logged or stored; capture stdout into a secret
/// store. In a `fips` build the same `STIG_FIPS_PENDING_ALGS=ML-DSA-87` gate as
/// the server applies. Refuses when stdout is a terminal, so the key does not
/// land in scrollback or a log driver by accident.
fn run_gen_mldsa_key(policy: &fips::FipsPolicy) -> Result<()> {
    use std::io::IsTerminal as _;
    check_gen_key_allowed(policy, std::io::stdout().is_terminal())?;
    let key = crypto::mldsa::SigningKey::generate()?;
    write_mldsa_key(
        &key,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

/// Preconditions of `gen-mldsa-key`: the pending-algorithm gate, and stdout
/// must not be a terminal.
fn check_gen_key_allowed(policy: &fips::FipsPolicy, stdout_is_terminal: bool) -> Result<()> {
    policy.require(fips::PendingAlg::MlDsa87)?;
    if stdout_is_terminal {
        anyhow::bail!(
            "refusing to print a private key to a terminal; redirect stdout to a file or a secret store (gen-mldsa-key > key.b64)"
        );
    }
    Ok(())
}

/// Key (one base64 PKCS#8 line) to `out`, key id only to `err`.
fn write_mldsa_key(
    key: &crypto::mldsa::SigningKey,
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> Result<()> {
    use base64::Engine as _;
    let der = key.to_pkcs8()?;
    let key_id = signers::key_id(signers::Algorithm::MlDsa87, &key.public_key());
    writeln!(
        out,
        "{}",
        base64::engine::general_purpose::STANDARD.encode(der)
    )?;
    writeln!(err, "ml-dsa-87 keyId: {key_id}")?;
    Ok(())
}

/// End a `migrate` run. Distinct exit codes let the dev compose loop retry
/// only transient failures. Same output shape as anyhow's default; no URL is
/// logged.
fn exit_migrate(result: Result<()>) -> ! {
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {e:?}");
            std::process::exit(db_roles::migrate_exit_code(&e));
        }
    }
}

/// CORS — cookie-based auth requires a specific origin (not "*") plus
/// `allow_credentials`. Allow the frontend origin from FRONTEND_URL.
/// `x-user-id` is only an allowed request header when the test-auth bypass is
/// on. `Retry-After` is exposed so a cross-origin frontend can read it.
fn cors_layer(origin: HeaderValue, test_hooks: &TestHooks) -> CorsLayer {
    let mut cors_headers = vec![header::CONTENT_TYPE, header::COOKIE];
    if test_hooks.allow_test_auth_header {
        cors_headers.push(header::HeaderName::from_static("x-user-id"));
    }
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers(cors_headers)
        .expose_headers([header::RETRY_AFTER])
        .allow_credentials(true)
}

/// Assemble the full application router: public routes, auth, SAML, the protected
/// stack, then the test-only routes (only when `test_hooks.enable_test_routes`), the
/// body limit and CORS. The layer order is load-bearing; see `router_tests`.
fn build_app(
    state: AppState,
    auth_state: AppAuthState,
    saml_state: AppSamlState,
    cors: CorsLayer,
    test_hooks: &TestHooks,
    static_site: Option<Arc<api::static_files::StaticSite>>,
) -> Router {
    // Auth flow routes — public, do not require an existing session.
    let auth_routes: Router = Router::new()
        .route("/auth/login", get(login_handler))
        .route("/auth/callback", get(callback_handler))
        .route("/auth/logout", post(logout_handler))
        .route(
            "/auth/notice/ack",
            post(api::notice::ack_handler).layer(axum::extract::DefaultBodyLimit::max(1024)),
        )
        .with_state(auth_state.clone());

    // SAML SP routes — also public. Built statically from env; if no IdP
    // SSO URL is configured the login route returns 503 with a helpful
    // message but /metadata still works (useful when handing the SP
    // metadata to an IdP admin to register us).
    let saml_routes: Router = Router::new()
        .route("/auth/saml/login", get(saml_login_handler))
        .route(
            "/auth/saml/acs",
            post(saml_acs_handler).layer(axum::extract::DefaultBodyLimit::max(
                api::saml::ACS_BODY_LIMIT,
            )),
        )
        .route("/auth/saml/metadata", get(saml_metadata_handler))
        .with_state(saml_state);

    // Draft + asset + /api/users/me routes — require an authenticated session.
    let draft_routes = api::authz_audit::protected_stack(
        Router::new()
            .route(
                "/api/assets",
                get(list_assets_handler).post(create_asset_handler),
            )
            .route("/api/assets/import", post(import_assets_handler))
            .route(
                "/api/assets/:id",
                get(get_asset_handler)
                    .put(update_asset_handler)
                    .patch(patch_asset_handler)
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
                "/api/assets/:id/email-cc",
                get(list_asset_email_cc_handler).post(create_asset_email_cc_handler),
            )
            .route(
                "/api/assets/:id/email-cc/:email",
                axum::routing::delete(delete_asset_email_cc_handler),
            )
            .route(
                "/api/assets/:id/email-report",
                post(send_asset_email_report_handler),
            )
            .route(
                "/api/assets/:id/checklists/save",
                post(
                    checklist_save_handler.layer(DefaultBodyLimit::max(SAVE_TO_SYSTEM_BODY_LIMIT)),
                ),
            )
            .route(
                "/api/checklist-sets",
                get(list_checklist_sets_handler).post(
                    create_checklist_set_handler
                        .layer(DefaultBodyLimit::max(CHECKLIST_SET_SMALL_BODY_LIMIT)),
                ),
            )
            .route(
                "/api/checklist-sets/:id",
                get(get_checklist_set_handler)
                    .patch(
                        patch_checklist_set_handler
                            .layer(DefaultBodyLimit::max(CHECKLIST_SET_SMALL_BODY_LIMIT)),
                    )
                    .delete(delete_checklist_set_handler),
            )
            .route(
                "/api/checklist-sets/:id/stigs",
                post(
                    add_checklist_set_stig_handler
                        .layer(DefaultBodyLimit::max(CHECKLIST_SET_SMALL_BODY_LIMIT)),
                ),
            )
            .route(
                "/api/checklist-sets/:id/stigs/:stig_id",
                axum::routing::delete(remove_checklist_set_stig_handler),
            )
            .route(
                "/api/checklist-sets/:id/rules",
                axum::routing::patch(
                    autosave_checklist_set_handler
                        .layer(DefaultBodyLimit::max(CHECKLIST_SET_AUTOSAVE_BODY_LIMIT)),
                ),
            )
            .route(
                "/api/checklist-sets/:id/save-to-system",
                post(
                    save_checklist_set_to_system_handler
                        .layer(DefaultBodyLimit::max(CHECKLIST_SET_SMALL_BODY_LIMIT)),
                ),
            )
            .route(
                "/api/asset-groups",
                get(list_asset_groups_handler).post(create_asset_group_handler),
            )
            .route(
                "/api/asset-groups/:id",
                axum::routing::patch(update_asset_group_handler).delete(delete_asset_group_handler),
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
            .route("/api/assets/:id/oscal.json", get(asset_oscal_handler))
            .route("/api/assets/:id/trend", get(asset_trend_handler))
            .route("/api/assets/:left/diff/:right", get(compare_assets_handler))
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
                "/api/checklists/:id/rules/bulk-status",
                post(rule_bulk_status_handler.layer(DefaultBodyLimit::max(BULK_STATUS_BODY_LIMIT))),
            )
            .route(
                "/api/checklists/:id/rules/:rule_id/history",
                get(rule_history_handler),
            )
            .route(
                "/api/checklists/:id/rules/:rule_id/attachments",
                get(list_attachments_for_rule_handler).post(
                    upload_attachment_handler.layer(DefaultBodyLimit::max(ATTACHMENT_BODY_LIMIT)),
                ),
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
                "/api/comments/:id/reactions",
                post(add_comment_reaction_handler),
            )
            .route(
                "/api/comments/:id/reactions/:reaction",
                axum::routing::delete(remove_comment_reaction_handler),
            )
            .route(
                "/api/checklists/:id/attachments",
                get(attachments_counts_for_checklist_handler),
            )
            .route(
                "/api/attachments/:id",
                get(download_attachment_handler).delete(delete_attachment_handler),
            )
            .route("/api/activity", get(activity_handler))
            .merge(api::audit::audited_reads_router())
            .route(
                "/api/drafts",
                get(list_drafts_handler).post(create_draft_handler),
            )
            .route("/api/drafts/pending-for-me", get(pending_for_me_handler))
            .route(
                "/api/drafts/from-stig/:stig_id",
                post(fork_from_stig_handler),
            )
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
            .route("/api/approvals/:id/approve", post(approve_finding_handler))
            .route("/api/approvals/:id/reject", post(reject_finding_handler))
            .route(
                "/api/assets/:id/approval-policy",
                axum::routing::patch(update_asset_approval_policy_handler),
            )
            .route("/api/notifications", get(get_notifications_handler))
            .route(
                "/api/notifications/mark-read",
                post(mark_notifications_read_handler),
            )
            .route(
                "/api/notifications/prefs",
                get(get_notification_prefs_handler).put(put_notification_prefs_handler),
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
            .route(
                "/api/baselines/:id",
                axum::routing::delete(delete_baseline_handler),
            )
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
            .route("/api/admin/failure-counters", get(failure_counters_handler))
            .route("/api/admin/backup", get(admin_backup_download_handler))
            // Backup archives can be as large as the catalog uploads; the
            // handler is admin-only.
            .route(
                "/api/admin/restore",
                post(admin_restore_handler).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
            )
            .route(
                "/api/admin/policies",
                get(list_abac_policies_handler).post(create_abac_policy_handler),
            )
            .route(
                "/api/admin/policies/:id",
                axum::routing::patch(update_abac_policy_handler).delete(delete_abac_policy_handler),
            )
            .route("/api/admin/sessions", get(list_active_sessions_handler))
            .route(
                "/api/admin/sessions/:id",
                axum::routing::delete(revoke_session_handler),
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
                axum::routing::patch(update_webhook_handler).delete(delete_webhook_handler),
            )
            .route(
                "/api/webhooks/:id/deliveries",
                get(list_webhook_deliveries_handler),
            )
            .route("/api/webhooks/:id/test", post(test_webhook_handler))
            .route(
                "/api/webhooks/:id/verify-recipe",
                get(webhook_verify_recipe_handler),
            )
            .route("/api/stigs/lint", post(stig_lint_handler))
            .route("/api/stigs/:id/diff", get(catalog_diff_handler))
            .route("/api/stigs/:id/archive", get(list_catalog_archive_handler))
            .route("/api/catalog/search", get(catalog_search_handler))
            // Detached signing for exported artifacts (.ckl bundles): Ed25519, or
            // Ed25519 + ML-DSA-87 when SIGNING_MLDSA87_KEY_B64 is set. Returns 503
            // when SIGNING_KEY_HEX isn't set.
            .route(
                "/api/sign",
                post(api::signing::sign_handler).layer(DefaultBodyLimit::max(SIGN_BODY_LIMIT)),
            )
            // Catalog uploads — admin-only (checked in the handlers) and the
            // only routes besides restore that accept bodies up to
            // MAX_UPLOAD_BYTES.
            .route(
                "/api/upload",
                post(upload_stig).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
            )
            .route(
                "/api/upload/library",
                post(upload_library).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
            ), // Viewer gate, central authz.denied recorder, request context,
        // admission cap and rate limiter (see `authz_audit::protected_stack` for the order).
        &state,
    )
    .route_layer(middleware::from_fn_with_state(
        auth_state.clone(),
        auth_middleware,
    ))
    .with_state(state.clone());

    let app = Router::new()
        .route("/api/health", get(get_health))
        .route("/api/catalog", get(get_catalog))
        .route("/api/stigs/:id", get(get_stig))
        // Public verifier key for offline signature verification. Returns
        // 503 when SIGNING_KEY_HEX isn't set.
        .route("/api/signing/pubkey", get(api::signing::pubkey_handler))
        .with_state(state.clone())
        .merge(auth_routes)
        .merge(saml_routes)
        .merge(draft_routes);

    let app = api::test_support::mount(app, test_hooks.enable_test_routes, state.clone());

    // Release frontend, same origin. A fallback, so every explicit route above
    // wins; it is attached before the layers below so it stays inside
    // `CatchPanicLayer`. Unset (dev, e2e) leaves the router unchanged.
    let app = match static_site {
        Some(site) => app.fallback(move |req: axum::extract::Request| {
            let site = site.clone();
            async move { site.respond(req.method(), req.uri().path()) }
        }),
        None => app,
    };

    // Inside CORS (so the 500 carries CORS headers) and outside every route and
    // middleware (so a panic anywhere below becomes a 500, not a dropped connection).
    app.layer(DefaultBodyLimit::max(DEFAULT_BODY_LIMIT))
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(cors)
}

/// 500 for a caught panic. The payload is logged, never returned.
fn panic_response(err: Box<dyn std::any::Any + Send + 'static>) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let msg = err
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| err.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload");
    tracing::error!(panic = msg, "request handler panicked");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({"error": "internal error"})),
    )
        .into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `gen-mldsa-key` prints the key on stdout, so its logs go to stderr.
    let log_writer = if args.first().map(String::as_str) == Some("gen-mldsa-key") {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "stig_viewer_backend=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(log_writer))
        .init();

    // Refuse to start when the FIPS build cannot confirm the FIPS module is
    // in FIPS mode, or STIG_REQUIRE_FIPS is set on a non-FIPS build. Must stay
    // before the migrate dispatch, DB access and bind (fail-closed, #64). The
    // guard applies to `migrate`; the audit event is written only on server
    // startup.
    let fips_startup = fips::startup_guard()?;
    // Outbound TLS (reqwest, lettre) runs on AWS-LC; install the provider
    // before any client is built (#215).
    crypto::tls::install(&fips_startup.policy)?;

    // `migrate`: run migrations and grants as the owner role, then exit.
    match db_roles::parse_command(&args)? {
        db_roles::Command::Migrate => exit_migrate(run_migrate_command().await),
        db_roles::Command::GenMldsaKey => return run_gen_mldsa_key(&fips_startup.policy),
        // Container HEALTHCHECK: probe the local server, no config or DB.
        db_roles::Command::Healthcheck => {
            let port = match std::env::var("PORT") {
                Ok(p) => p
                    .parse::<u16>()
                    .context("PORT must be a valid port number")?,
                Err(_) => 8080,
            };
            if let Err(e) = api::health::probe(port) {
                eprintln!("healthcheck failed: {e:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
        db_roles::Command::Serve => {}
    }

    // Test-only hooks are opt-in, and a production deployment that has one
    // enabled refuses to start — before touching the DB or binding a port.
    let test_hooks = TestHooks::from_env();
    test_hooks.validate()?;
    warn_enabled_test_hooks(&test_hooks);

    let config = Arc::new(Config::from_env()?);
    config::validate_seed_dir(
        std::env::var("STIG_ENV").ok().as_deref(),
        config.seed_dir.as_deref(),
    )?;
    // A bad ADMISSION_BODY_* value stops startup here; wiring is tested in
    // `config::tests::a_bad_admission_body_env_value_is_an_error_naming_the_variable`.
    let admission_body = config::AdmissionBody::from_env()?;
    info!(
        first_byte_secs = admission_body.first_byte.as_secs(),
        grace_secs = admission_body.grace.as_secs(),
        min_rate_bytes_per_sec = admission_body.min_rate,
        "admission body limits"
    );
    let sources = Arc::new(load_sources()?);

    info!(
        "Loaded {} STIG sources, data_dir={}",
        sources.len(),
        config.data_dir.display()
    );

    tokio::fs::create_dir_all(config.data_dir.join("stigs")).await?;

    let pool = Arc::new(open_database(&config, &test_hooks).await?);
    fips::record_policy_event(&pool, &fips_startup).await;
    let _ = stig_id::warn_non_conforming(&pool).await;

    if let Some(seed_dir) = &config.seed_dir {
        seed::seed(seed_dir, &config.data_dir.join("stigs"), &pool, &sources).await;
    }
    seed::warn_orphaned_ids(&pool, &sources, config.seed_dir.as_deref()).await;

    // ── Signing (optional) ──────────────────────────────────────────────────
    let signing = api::signing::SigningState::from_env(&fips_startup.policy)?;
    match &signing {
        Some(s) => {
            info!(
                profile = s.profile().as_str(),
                key_ids = %s.key_ids().join(","),
                require_hybrid = s.require_hybrid,
                "Signing enabled (key_id={})",
                s.key_id
            );
            if s.mldsa.is_none() {
                tracing::warn!(
                    "Signing is classical (Ed25519 only): set SIGNING_MLDSA87_KEY_B64 for hybrid ML-DSA-87 signatures"
                );
            }
        }
        None => info!("Signing disabled (SIGNING_KEY_HEX not set)"),
    }

    // ── OIDC setup ──────────────────────────────────────────────────────────
    let oidc_env = OidcEnv::from_env(test_hooks.allow_test_auth_header)?;
    let frontend_origin = oidc_env.frontend_url.clone();
    let oidc = build_oidc_context(&oidc_env).await?;
    info!(
        "OIDC client ready (issuer={}, test_header_auth={})",
        oidc_env.internal_issuer_url, oidc_env.allow_test_auth_header
    );

    api::notice::log_proxy_trust_config();
    let tasks = detached::Tracker::new();
    let auth_state = AppAuthState {
        pool: pool.clone(),
        oidc: oidc.clone(),
        tasks: tasks.clone(),
    };

    let cors = cors_layer(frontend_origin.parse::<HeaderValue>()?, &test_hooks);

    let state = AppState {
        pool: pool.clone(),
        config: config.clone(),
        signing: signing.clone(),
        tasks: tasks.clone(),
        admission: api::admission::Admission::configured(admission_body.into()),
    };

    let saml_config = Arc::new(SamlConfig::from_env(&frontend_origin)?);
    info!(
        "SAML SP ready (configured={}, sp_entity_id={}, acs_url={})",
        saml_config.is_configured(),
        saml_config.sp_entity_id,
        saml_config.sp_acs_url,
    );
    let saml_state = AppSamlState {
        pool: pool.clone(),
        config: saml_config.clone(),
        tasks: tasks.clone(),
    };
    let static_site = match config.static_dir.as_deref() {
        Some(dir) => Some(Arc::new(
            api::static_files::StaticSite::load(
                dir,
                config::is_production(std::env::var("STIG_ENV").ok().as_deref()),
            )
            .with_context(|| format!("STIG_STATIC_DIR={}", dir.display()))?,
        )),
        None => None,
    };
    let app = build_app(
        state.clone(),
        auth_state,
        saml_state,
        cors,
        &test_hooks,
        static_site,
    );

    {
        let cfg = config.clone();
        let src = sources.clone();
        let db = pool.clone();
        tokio::spawn(async move {
            let period = Duration::from_secs(cfg.sync_interval_hours * 3600);
            // `interval` fires its first tick immediately; with
            // STIG_SYNC_ON_START=false start the schedule one period out.
            let mut interval = if cfg.sync_on_start {
                tokio::time::interval(period)
            } else {
                info!(
                    "STIG_SYNC_ON_START is off: first DISA sync in {} hour(s)",
                    cfg.sync_interval_hours
                );
                tokio::time::interval_at(tokio::time::Instant::now() + period, period)
            };
            loop {
                interval.tick().await;
                let result = scheduler_log::record(&db, "sync", || async {
                    let summary = sync::run_sync(&cfg, &src, &db).await?;
                    Ok::<String, anyhow::Error>(summary.describe())
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
            let mut interval = tokio::time::interval(Duration::from_secs(snap_hours * 3600));
            loop {
                interval.tick().await;
                let result = scheduler_log::record(&db, "snapshot", || async {
                    let n = take_snapshot(&db).await.map_err(anyhow::Error::from)?;
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
            let mut interval = tokio::time::interval(Duration::from_secs(digest_hours * 3600));
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
        let retain_days: i64 = audit_retention::retain_days_from_env();
        let archive_enabled: bool = std::env::var("AUDIT_ARCHIVE_ENABLED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true);
        let db = pool.clone();
        let cfg = config.clone();
        let retention_signing = signing.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(retention_hours * 3600));
            loop {
                interval.tick().await;
                let result = scheduler_log::record(&db, "audit_retention", || async {
                    audit_retention::run_scheduled(
                        &db,
                        &cfg.data_dir,
                        retain_days,
                        archive_enabled,
                        retention_signing.as_ref(),
                    )
                    .await
                })
                .await;
                match result {
                    Ok(msg) => tracing::info!("audit retention: {msg}"),
                    Err(e) => tracing::error!("audit retention failed: {e:#}"),
                }
            }
        });
    }

    // Test-mode flag re-check (#106): its own short interval, log and audit
    // only. The audit row is written on a transition, the log line every time.
    tokio::spawn(db_audit::run_test_flag_recheck(
        (*pool).clone(),
        test_hooks.enable_test_routes,
        db_audit::TEST_FLAG_RECHECK_INTERVAL,
    ));

    // Held-back audit shed-log summaries, so counts show up after a flood stops.
    tokio::spawn(db_audit::run_shed_flush(db_audit::SHED_FLUSH_INTERVAL));

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
            let mut interval = tokio::time::interval(Duration::from_secs(report_hours * 3600));
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

    // Per-asset scheduled email scheduler — fires the existing per-asset
    // compliance-report email path on a daily / weekly / monthly cadence
    // chosen by each asset's owner. The cadence-interval check lives in
    // `run_asset_email_schedules` (SQL `INTERVAL`-driven), so the loop
    // itself can tick on a coarse hourly default and let assets that
    // aren't yet due fall out via the SELECT.
    {
        let interval_hours: u64 = std::env::var("ASSET_EMAIL_SCHEDULE_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let db = pool.clone();
        let cfg = config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_hours * 3600));
            loop {
                interval.tick().await;
                let result = scheduler_log::record(&db, "asset_email_schedule", || async {
                    let n = run_asset_email_schedules(&db, &cfg.data_dir).await?;
                    Ok::<String, anyhow::Error>(format!("emailed {n} asset(s)"))
                })
                .await;
                match result {
                    Ok(msg) => tracing::info!("asset email schedule: {msg}"),
                    Err(e) => tracing::error!("asset email schedule failed: {e:#}"),
                }
            }
        });
    }

    // AC-8: drop consumed login acknowledgements whose claim window has passed;
    // the same tick prunes expired SAML replay-cache rows (#62).
    // Deliberately not registered with `scheduler_log` (not a status-page scheduler);
    // failures are counted: status on `/api/health` (`checks.loginAckPrune`),
    // numbers on the admin-only `/api/admin/failure-counters`.
    {
        let db = pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                db_notice::prune_acks_tick(&db, &failure_counters::ACK_PRUNE).await;
                db_saml_replay::prune_tick(&db).await;
            }
        });
    }

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on http://{addr}");

    // The drain budget starts at the shutdown signal and covers both the
    // server's graceful phase (which waits for open connections) and the wait
    // for detached work and audit writes.
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel();
    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = signalled_tx.send(tokio::time::Instant::now());
    });
    let outcome = serve_until_drained(
        std::future::IntoFuture::into_future(serve),
        signalled_rx,
        async {
            state.tasks.idle().await;
            db_audit::drain().await;
        },
        SHUTDOWN_DRAIN,
    )
    .await;
    // Every exit path: held-back shed counts would otherwise be lost.
    db_audit::flush_shed_summaries();
    let outcome = outcome?;
    if outcome == ShutdownOutcome::BudgetExpired {
        let (_, pending, _) = db_audit::write_stats();
        tracing::error!(
            target: "audit",
            in_flight = state.tasks.in_flight(),
            pending_audit_writes = pending,
            "shutdown budget of {SHUTDOWN_DRAIN:?} from the signal expired; \
             open requests and pending work are lost"
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ShutdownOutcome {
    /// The server stopped without a signal (an accept error already returned).
    ServerStopped,
    /// Signalled; the server and `drain` finished within the budget.
    Drained,
    /// Signalled; the budget expired first and pending work is abandoned.
    BudgetExpired,
}

/// Run `serve` until it ends or `signal_rx` reports the shutdown signal, then
/// give it and `drain` until `budget` after the signal to finish.
async fn serve_until_drained<S, D>(
    serve: S,
    mut signal_rx: tokio::sync::oneshot::Receiver<tokio::time::Instant>,
    drain: D,
    budget: Duration,
) -> Result<ShutdownOutcome>
where
    S: std::future::Future<Output = std::io::Result<()>>,
    D: std::future::Future<Output = ()>,
{
    let mut serve = std::pin::pin!(serve);
    let signalled_at = tokio::select! {
        r = &mut serve => {
            // The server stopped without a signal (an accept error).
            r?;
            return Ok(ShutdownOutcome::ServerStopped);
        }
        Ok(at) = &mut signal_rx => at,
    };
    let drained = tokio::time::timeout_at(signalled_at + budget, async {
        let served = (&mut serve).await;
        drain.await;
        served
    })
    .await;
    match drained {
        Ok(served) => {
            served?;
            Ok(ShutdownOutcome::Drained)
        }
        Err(_) => Ok(ShutdownOutcome::BudgetExpired),
    }
}

/// Total shutdown budget, measured from the signal: the server's graceful
/// phase plus detached work and audit writes. The dev compose file sets
/// `stop_grace_period: 15s` (production should allow at least 15 s) and its
/// entrypoint delivers SIGTERM to this process; stay below that, leaving room
/// for the HTTP server's own graceful shutdown. A write still running at the
/// expiry is logged here and lost (the 30 s hard write cap is longer on purpose:
/// it bounds a hung database, not a normal stop).
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(8);

/// Resolves on SIGTERM (never, off unix or if the handler cannot install).
async fn terminate_signal() {
    #[cfg(unix)]
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut s) => {
            s.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            // No handler: never resolve on this branch.
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate_signal() => {},
    }
    info!("Shutting down…");
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;
    use tokio::sync::oneshot;

    const BUDGET: Duration = Duration::from_secs(8);

    #[tokio::test]
    async fn shutdown_drains_pending_work_within_the_budget() {
        let (tx, rx) = oneshot::channel();
        let drained = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = drained.clone();
        let _ = tx.send(tokio::time::Instant::now());
        let out = serve_until_drained(
            // Finishes only after the signal was seen, as a graceful server does.
            async {
                tokio::task::yield_now().await;
                Ok(())
            },
            rx,
            async move {
                tokio::task::yield_now().await;
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            },
            BUDGET,
        )
        .await
        .unwrap();
        assert_eq!(out, ShutdownOutcome::Drained);
        assert!(drained.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_budget_expiry_abandons_pending_work() {
        let (tx, rx) = oneshot::channel();
        let start = tokio::time::Instant::now();
        let serve = async {
            std::future::pending::<()>().await;
            Ok(())
        };
        let _ = tx.send(start);
        let out = serve_until_drained(serve, rx, std::future::pending::<()>(), BUDGET)
            .await
            .unwrap();
        assert_eq!(out, ShutdownOutcome::BudgetExpired);
        assert_eq!(tokio::time::Instant::now() - start, BUDGET);
    }

    #[tokio::test]
    async fn a_server_that_stops_without_a_signal_skips_the_drain() {
        let (_tx, rx) = oneshot::channel();
        let out = serve_until_drained(
            async { Ok(()) },
            rx,
            async { panic!("the drain must not run without a signal") },
            BUDGET,
        )
        .await
        .unwrap();
        assert_eq!(out, ShutdownOutcome::ServerStopped);
    }

    #[tokio::test]
    async fn a_server_error_without_a_signal_is_returned() {
        let (_tx, rx) = oneshot::channel();
        let r = serve_until_drained(
            async { Err(std::io::Error::other("accept failed")) },
            rx,
            async {},
            BUDGET,
        )
        .await;
        assert!(r.is_err());
    }

    /// `tokio::signal` handlers are never uninstalled, so the check runs in a
    /// re-executed child of this test binary; the parent's signal disposition
    /// stays untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_signal_resolves_on_sigterm() {
        const GUARD: &str = "STIG_TERMINATE_SIGNAL_CHILD";
        const NAME: &str = "shutdown_tests::terminate_signal_resolves_on_sigterm";
        if std::env::var_os(GUARD).is_none() {
            let exe = std::env::current_exe().unwrap();
            let status = std::process::Command::new(exe)
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(GUARD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "child failed: {status:?}");
            return;
        }
        let mut term = Box::pin(terminate_signal());
        // First poll installs the handler.
        let pending = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(term.as_mut(), cx).is_pending())
        })
        .await;
        assert!(pending);
        let status = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        tokio::time::timeout(Duration::from_secs(5), term)
            .await
            .expect("SIGTERM resolves terminate_signal");
    }
}

#[cfg(test)]
mod router_tests {
    //! Drives the assembled router from `build_app`, so the test-route gate is
    //! proven on the real layer stack and not only on `test_support::mount`.
    //! A `DELETE` (no route uses it) answers 405 on a mounted path and 404 on
    //! an unmounted one without running a handler, so no database is needed.
    use super::*;
    use axum::{body::Body, http::Request, http::StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn a_panicking_route_becomes_a_generic_500_with_cors() {
        async fn boom() -> &'static str {
            panic!("secret-detail");
        }
        let app = Router::new()
            .route("/boom", get(boom))
            .layer(CatchPanicLayer::custom(panic_response))
            .layer(CorsLayer::permissive());
        let res = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(res.headers().contains_key("access-control-allow-origin"));
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"internal error"}"#);
    }

    fn app(hooks: &TestHooks) -> (Router, test_fixtures::StigDir) {
        let (state, dir) = test_fixtures::lazy_state();
        let auth = test_fixtures::auth_state(&state);
        let saml = test_fixtures::saml_state(&state);
        (
            build_app(state, auth, saml, CorsLayer::new(), hooks, None),
            dir,
        )
    }

    async fn status(app: &Router, method: &str, uri: &str, body: Option<&str>) -> StatusCode {
        let mut req = Request::builder().method(method).uri(uri);
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        app.clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn test_routes_are_404_when_the_flag_is_off() {
        // The auth-header flag is on to show it is not what gates the routes.
        let hooks = TestHooks {
            production: false,
            enable_test_routes: false,
            allow_test_auth_header: true,
        };
        let (app, _dir) = app(&hooks);
        for path in api::test_support::route_paths() {
            for method in ["POST", "GET", "DELETE"] {
                assert_eq!(
                    status(&app, method, path, None).await,
                    StatusCode::NOT_FOUND,
                    "{method} {path}"
                );
            }
        }
        assert_ne!(
            status(&app, "GET", "/api/health", None).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_routes_are_served_when_the_flag_is_on() {
        let hooks = TestHooks {
            production: false,
            enable_test_routes: true,
            allow_test_auth_header: false,
        };
        let (app, _dir) = app(&hooks);
        for path in api::test_support::route_paths() {
            assert_eq!(
                status(&app, "DELETE", path, None).await,
                StatusCode::METHOD_NOT_ALLOWED,
                "DELETE {path}"
            );
        }
        assert_eq!(
            status(
                &app,
                "POST",
                "/api/test/inject-scheduler-error",
                Some(r#"{"name":"nope"}"#)
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    // ---- SAML ACS through the real router (no database) ----

    use std::net::SocketAddr;

    /// A body with no `Content-Length`: a run of equal-sized chunks.
    struct Chunks {
        left: usize,
        chunk: usize,
    }

    impl http_body::Body for Chunks {
        type Data = axum::body::Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            if self.left == 0 {
                return std::task::Poll::Ready(None);
            }
            let n = self.left.min(self.chunk);
            self.left -= n;
            std::task::Poll::Ready(Some(Ok(http_body::Frame::data(axum::body::Bytes::from(
                vec![b'A'; n],
            )))))
        }
    }

    async fn acs(app: &Router, body: Body, peer: Option<SocketAddr>) -> axum::response::Response {
        let mut req = Request::builder()
            .method("POST")
            .uri("/auth/saml/acs")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .unwrap();
        if let Some(p) = peer {
            req.extensions_mut().insert(axum::extract::ConnectInfo(p));
        }
        app.clone().oneshot(req).await.unwrap()
    }

    async fn body_text(r: axum::response::Response) -> String {
        let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        String::from_utf8_lossy(&b).into_owned()
    }

    fn acs_app() -> (Router, test_fixtures::StigDir) {
        app(&TestHooks {
            production: false,
            enable_test_routes: false,
            allow_test_auth_header: false,
        })
    }

    fn form_of_len(total: usize) -> String {
        let prefix = "SAMLResponse=";
        format!("{prefix}{}", "!".repeat(total - prefix.len()))
    }

    #[tokio::test]
    async fn saml_acs_over_its_body_limit_is_413() {
        let (app, _dir) = acs_app();
        let prefix = "SAMLResponse=";
        let big = format!("{prefix}{}", "A".repeat(api::saml::ACS_BODY_LIMIT));
        let r = acs(&app, Body::from(big), None).await;
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(r.headers().get("set-cookie").is_none());
        let text = body_text(r).await;
        assert!(text.len() < 200, "{text}");
        assert!(!text.contains("AAAA"));

        // No Content-Length: the limit still applies while streaming.
        let streamed = Body::new(Chunks {
            left: api::saml::ACS_BODY_LIMIT + 1024,
            chunk: 16 * 1024,
        });
        let r = acs(&app, streamed, None).await;
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(r.headers().get("set-cookie").is_none());
    }

    #[tokio::test]
    async fn saml_acs_at_its_body_limit_reaches_the_handler() {
        let (app, _dir) = acs_app();
        let r = acs(
            &app,
            Body::from(form_of_len(api::saml::ACS_BODY_LIMIT)),
            None,
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_text(r).await, "SAML authentication failed");
    }

    #[tokio::test]
    async fn saml_acs_route_consults_the_global_pre_auth_limiter() {
        use api::rate_limit::{global, limiter_key};
        let (app, _dir) = acs_app();
        let ip = "198.51.100.86";
        let peer = SocketAddr::new(ip.parse().unwrap(), 4000);
        let other = SocketAddr::new("198.51.100.87".parse().unwrap(), 4000);
        let small = || Body::from("SAMLResponse=!");
        // test_support::reset_handler can clear the global limiter concurrently.
        let mut limited = None;
        for _ in 0..3 {
            let r = acs(&app, small(), Some(peer)).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
            let key = limiter_key(ip);
            let mut drained = false;
            for _ in 0..100_000 {
                if !global().allow(&key) {
                    drained = true;
                    break;
                }
            }
            assert!(drained, "limiter never drained");
            let r = acs(&app, small(), Some(peer)).await;
            if r.status() == StatusCode::TOO_MANY_REQUESTS {
                limited = Some(r);
                break;
            }
        }
        let r = limited.expect("a 429 within 3 attempts");
        assert!(r.headers().get("set-cookie").is_none());
        assert_eq!(body_text(r).await, "too many requests");
        let r = acs(&app, small(), Some(other)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cors_exposes_retry_after_to_the_frontend_origin() {
        let origin = "http://localhost:15173";
        let cors = cors_layer(
            origin.parse::<HeaderValue>().unwrap(),
            &TestHooks {
                production: false,
                enable_test_routes: false,
                allow_test_auth_header: false,
            },
        );
        let (state, _dir) = test_fixtures::lazy_state();
        let auth = test_fixtures::auth_state(&state);
        let saml = test_fixtures::saml_state(&state);
        let hooks = TestHooks {
            production: false,
            enable_test_routes: false,
            allow_test_auth_header: false,
        };
        let app = build_app(state, auth, saml, cors, &hooks, None);
        let req = Request::builder()
            .uri("/api/health")
            .header("origin", origin)
            .body(Body::empty())
            .unwrap();
        let r = app.oneshot(req).await.unwrap();
        let exposed = r
            .headers()
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            exposed.to_ascii_lowercase().contains("retry-after"),
            "{exposed}"
        );
    }

    // ---- Static frontend fallback (no database needed) ----

    fn static_app(with_site: bool) -> (Router, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("svw-router-static-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), "<html>shell</html>").unwrap();
        std::fs::write(dir.join("app-0123456789abcdef.js"), "js").unwrap();
        let site =
            with_site.then(|| Arc::new(api::static_files::StaticSite::load(&dir, false).unwrap()));
        let (state, _d) = test_fixtures::lazy_state();
        let auth = test_fixtures::auth_state(&state);
        let saml = test_fixtures::saml_state(&state);
        let hooks = TestHooks {
            production: false,
            enable_test_routes: false,
            allow_test_auth_header: false,
        };
        (
            build_app(state, auth, saml, CorsLayer::new(), &hooks, site),
            dir,
        )
    }

    #[tokio::test]
    async fn static_fallback_serves_shell_and_keeps_api_misses_404() {
        let (app, dir) = static_app(true);
        for uri in ["/", "/assets/x", "/some/deep/link"] {
            let res = send_plain(&app, "GET", uri).await;
            assert_eq!(res.status(), StatusCode::OK, "{uri}");
            assert_eq!(res.headers()["x-frame-options"], "DENY", "{uri}");
            assert_eq!(res.headers()["x-content-type-options"], "nosniff", "{uri}");
        }
        let res = send_plain(&app, "GET", "/app-0123456789abcdef.js").await;
        assert_eq!(
            res.headers()["cache-control"],
            "public, max-age=31536000, immutable"
        );
        for uri in ["/api/nope", "/auth/nope", "/api", "/auth"] {
            assert_eq!(
                send_plain(&app, "GET", uri).await.status(),
                StatusCode::NOT_FOUND,
                "{uri}"
            );
        }
        // A real route is not shadowed by the fallback: health is never the
        // HTML shell (the lazy pool has no database, so it answers 503 JSON).
        let res = send_plain(&app, "GET", "/api/health").await;
        assert_ne!(res.headers()["content-type"], "text/html; charset=utf-8");
        assert_eq!(
            send_plain(&app, "POST", "/").await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn without_a_static_site_unknown_paths_stay_404() {
        let (app, dir) = static_app(false);
        assert_eq!(
            send_plain(&app, "GET", "/").await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send_plain(&app, "GET", "/some/deep/link").await.status(),
            StatusCode::NOT_FOUND
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    async fn send_plain(app: &Router, method: &str, uri: &str) -> axum::response::Response {
        let req = Request::builder().method(method).uri(uri);
        app.clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    // ---- Admission through the real router (needs Postgres) ----

    use api::admission::{
        Admission, ADMIN_RESERVE, AUDITED_READ_ROUTES, AUDIT_BACKLOG_HIGH, MAX_IN_FLIGHT,
        MAX_USER_IN_FLIGHT,
    };
    use sqlx::PgPool;
    use std::sync::atomic::AtomicU32;

    /// The assembled router with the test auth header on: `X-User-Id` names
    /// the caller (the user must be seeded; its id is the header value).
    fn db_app(state: AppState) -> Router {
        db_app_with(state, false)
    }

    /// [`db_app`] with the test routes mounted when `enable_test_routes`.
    fn db_app_with(state: AppState, enable_test_routes: bool) -> Router {
        let mut auth = test_fixtures::auth_state(&state);
        auth.oidc.allow_test_auth_header = true;
        let saml = test_fixtures::saml_state(&state);
        let hooks = TestHooks {
            production: false,
            enable_test_routes,
            allow_test_auth_header: true,
        };
        build_app(state, auth, saml, CorsLayer::new(), &hooks, None)
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        user: Option<&str>,
        body: Option<&str>,
    ) -> axum::response::Response {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(u) = user {
            req = req.header("X-User-Id", u);
        }
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        app.clone().oneshot(req.body(body).unwrap()).await.unwrap()
    }

    const CREATE: &str = r#"{"name":"admission set","stigIds":["TEST-STIG"]}"#;

    async fn count(pool: &PgPool, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(pool)
            .await
            .unwrap()
    }

    fn retry_after(r: &axum::response::Response) -> Option<String> {
        r.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_checklist_set_create_is_refused_at_a_full_cap_and_changes_nothing(pool: PgPool) {
        test_fixtures::seed_user(&pool, "cap-user").await;
        sqlx::query(
            "INSERT INTO stigs_catalog (id, title, category, version, release_info, json_path) \
             VALUES ($1, $1, 'x', '2', 'R3', '')",
        )
        .bind(test_fixtures::STIG_ID)
        .execute(&pool)
        .await
        .unwrap();
        let (state, _dir) = test_fixtures::app_state(pool.clone());
        let adm = state.admission.clone();
        let app = db_app(state.clone());

        // Per-user cap: 429.
        let mine: Vec<_> = (0..MAX_USER_IN_FLIGHT)
            .map(|_| adm.try_admit("cap-user").unwrap())
            .collect();
        let r = send(
            &app,
            "POST",
            "/api/checklist-sets",
            Some("cap-user"),
            Some(CREATE),
        )
        .await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after(&r).as_deref(), Some("1"));
        assert_eq!(
            (
                count(&pool, "checklist_sets").await,
                count(&pool, "audit_events").await
            ),
            (0, 0)
        );
        drop(mine);

        // Global cap for non-admins: 503.
        let others: Vec<_> = (0..(MAX_IN_FLIGHT - ADMIN_RESERVE) / MAX_USER_IN_FLIGHT)
            .flat_map(|u| (0..MAX_USER_IN_FLIGHT).map(move |_| u))
            .map(|u| adm.try_admit(&format!("other-{u}")).unwrap())
            .collect();
        let r = send(
            &app,
            "POST",
            "/api/checklist-sets",
            Some("cap-user"),
            Some(CREATE),
        )
        .await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after(&r).as_deref(), Some("1"));
        assert_eq!(
            (
                count(&pool, "checklist_sets").await,
                count(&pool, "audit_events").await
            ),
            (0, 0)
        );
        drop(others);

        // Audit backlog: 503 with the longer Retry-After.
        let gauge: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(AUDIT_BACKLOG_HIGH)));
        let mut backlogged = state.clone();
        backlogged.admission = Admission::with_backlog(gauge);
        let r = send(
            &db_app(backlogged),
            "POST",
            "/api/checklist-sets",
            Some("cap-user"),
            Some(CREATE),
        )
        .await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(retry_after(&r).as_deref(), Some("5"));
        assert_eq!(
            (
                count(&pool, "checklist_sets").await,
                count(&pool, "audit_events").await
            ),
            (0, 0)
        );

        // Released: the same request succeeds.
        let r = send(
            &app,
            "POST",
            "/api/checklist-sets",
            Some("cap-user"),
            Some(CREATE),
        )
        .await;
        assert_eq!(r.status(), StatusCode::CREATED);
        adm.idle().await;
        crate::db_audit::drain().await;
        assert_eq!(count(&pool, "checklist_sets").await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn public_health_is_unaffected_by_admission_refusals(pool: PgPool) {
        test_fixtures::seed_user(&pool, "health-user").await;
        let (state, _dir) = test_fixtures::app_state(pool.clone());
        let adm = state.admission.clone();
        let app = db_app(state);
        // The status can depend on process-wide audit counters, so compare
        // against the status before the fill instead of asserting 200.
        let before = send(&app, "GET", "/api/health", None, None).await.status();

        let _held: Vec<_> = (0..(MAX_IN_FLIGHT - ADMIN_RESERVE) / MAX_USER_IN_FLIGHT)
            .flat_map(|u| (0..MAX_USER_IN_FLIGHT).map(move |_| (u, false)))
            .map(|(u, _)| adm.try_admit(&format!("fill-{u}")).unwrap())
            .chain((0..ADMIN_RESERVE).map(|_| adm.try_admit_as("admin-fill", true).unwrap()))
            .collect();
        assert_eq!(adm.in_flight(), MAX_IN_FLIGHT);
        let r = send(
            &app,
            "POST",
            "/api/checklist-sets",
            Some("health-user"),
            Some(CREATE),
        )
        .await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let stats = adm.stats();
        assert!(stats.refused_global >= 1);

        for _ in 0..2 {
            let r = send(&app, "GET", "/api/health", None, None).await;
            assert_eq!(r.status(), before);
            assert!(retry_after(&r).is_none());
            let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(v.get("checks").is_some(), "{v}");
        }
        assert_eq!(
            adm.stats(),
            stats,
            "health neither takes nor refuses a permit"
        );
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn the_system_audit_event_test_route_works_through_the_full_router(pool: PgPool) {
        let rows = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_events WHERE user_id IS NULL \
                 AND user_role = 'system' AND action = 'catalog.sync'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        let (state, _dir) = test_fixtures::app_state(pool.clone());
        let on = db_app_with(state, true);
        let r = send(&on, "POST", "/api/test/system-audit-event", None, None).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT);
        crate::db_audit::drain().await;
        assert_eq!(rows().await, 1);

        let (state, _dir2) = test_fixtures::app_state(pool.clone());
        let off = db_app_with(state, false);
        let r = send(&off, "POST", "/api/test/system-audit-event", None, None).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        crate::db_audit::drain().await;
        assert_eq!(rows().await, 1);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn audited_read_routes_match_the_real_router(pool: PgPool) {
        test_fixtures::seed_user(&pool, "reader-admin").await;
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = 'reader-admin'")
            .execute(&pool)
            .await
            .unwrap();
        let (state, _dir) = test_fixtures::app_state(pool.clone());
        let adm = state.admission.clone();
        let app = db_app(state);
        let reads = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT COALESCE(SUM(repeat_count), 0)::bigint FROM audit_events \
                 WHERE action = 'audit.read'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        };

        let held: Vec<_> = (0..MAX_USER_IN_FLIGHT)
            .map(|_| adm.try_admit_as("reader-admin", true).unwrap())
            .collect();
        for route in AUDITED_READ_ROUTES {
            for method in ["GET", "HEAD"] {
                let r = send(&app, method, route, Some("reader-admin"), None).await;
                assert_eq!(
                    r.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "{method} {route}"
                );
            }
        }
        // Control: a read that records nothing is not admitted, so not refused.
        let r = send(
            &app,
            "GET",
            "/api/checklist-sets",
            Some("reader-admin"),
            None,
        )
        .await;
        assert_ne!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(reads().await, 0);
        drop(held);

        let mut expected = 0;
        for route in AUDITED_READ_ROUTES {
            let r = send(&app, "GET", route, Some("reader-admin"), None).await;
            assert_eq!(r.status(), StatusCode::OK, "GET {route}");
            adm.idle().await;
            crate::db_audit::drain().await;
            expected += 1;
            assert_eq!(reads().await, expected, "one audit.read row for {route}");
        }
    }
}

#[cfg(test)]
mod gen_key_tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn gen_mldsa_key_refuses_a_terminal_and_an_ungated_enforced_policy() {
        let open = fips::FipsPolicy::from_vars(false, None).unwrap();
        assert!(check_gen_key_allowed(&open, false).is_ok());
        let e = check_gen_key_allowed(&open, true).unwrap_err().to_string();
        assert!(e.contains("terminal"), "{e}");
        let enforced = fips::FipsPolicy::from_vars(true, None).unwrap();
        let e = check_gen_key_allowed(&enforced, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("ML-DSA-87"), "{e}");
        let listed = fips::FipsPolicy::from_vars(true, Some("ML-DSA-87")).unwrap();
        assert!(check_gen_key_allowed(&listed, false).is_ok());
    }

    #[test]
    fn gen_mldsa_key_prints_one_pkcs8_line_and_the_key_id_only_on_stderr() {
        let key = crypto::mldsa::SigningKey::generate().unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        write_mldsa_key(&key, &mut out, &mut err).unwrap();
        let out = String::from_utf8(out).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert_eq!(out.matches('\n').count(), 1);
        let der = base64::engine::general_purpose::STANDARD
            .decode(out.trim_end())
            .unwrap();
        let loaded = crypto::mldsa::SigningKey::from_pkcs8(&der).unwrap();
        let id = signers::key_id(signers::Algorithm::MlDsa87, &loaded.public_key());
        assert_eq!(err, format!("ml-dsa-87 keyId: {id}\n"));
        assert!(!out.contains(&id) && !err.contains(out.trim_end()));
    }
}
