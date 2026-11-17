//! Shared helpers for the database-backed tests (`#[sqlx::test]`).
//!
//! Each such test gets a fresh database with `./migrations` applied; they are
//! `#[ignore]`d so a plain `cargo test` needs no Postgres. Run them with
//! `DATABASE_URL=... cargo test -- --include-ignored` (see `task test:db`).

use std::sync::Arc;

use sqlx::PgPool;

use crate::api::auth::AuthUser;
use crate::config::Config;
use crate::AppState;

/// Rule ids in the fixture STIG written by [`app_state`].
pub const STIG_ID: &str = "TEST-STIG";
pub const RULES: [&str; 3] = ["SV-1r1_rule", "SV-2r1_rule", "SV-3r1_rule"];

pub async fn seed_user(pool: &PgPool, id: &str) {
    sqlx::query("INSERT INTO users (id, display_name, email, role, sub, provider) VALUES ($1, $1, '', 'author', $1, 'test')")
        .bind(id)
        .execute(pool)
        .await
        .expect("seed user");
}

pub async fn seed_asset(pool: &PgPool, id: &str, owner: &str, requires_approval: bool) {
    sqlx::query("INSERT INTO assets (id, name, owner_id, requires_approval) VALUES ($1, $1, $2, $3)")
        .bind(id)
        .bind(owner)
        .bind(requires_approval)
        .execute(pool)
        .await
        .expect("seed asset");
}

pub async fn seed_acl(pool: &PgPool, asset_id: &str, user_id: &str, permission: &str) {
    sqlx::query("INSERT INTO asset_acl (asset_id, user_id, permission, granted_by) VALUES ($1, $2, $3, $2)")
        .bind(asset_id)
        .bind(user_id)
        .bind(permission)
        .execute(pool)
        .await
        .expect("seed acl");
}

pub async fn seed_tag(pool: &PgPool, asset_id: &str, tag: &str) {
    sqlx::query("INSERT INTO asset_tags (asset_id, tag) VALUES ($1, $2)")
        .bind(asset_id)
        .bind(tag)
        .execute(pool)
        .await
        .expect("seed tag");
}

pub async fn set_classification(pool: &PgPool, asset_id: &str, classification: &str) {
    sqlx::query("UPDATE assets SET classification = $2 WHERE id = $1")
        .bind(asset_id)
        .bind(classification)
        .execute(pool)
        .await
        .expect("set classification");
}

/// An ABAC policy created by `created_by` (must exist). `None` match = wildcard.
#[allow(clippy::too_many_arguments)]
pub async fn seed_policy(
    pool: &PgPool,
    name: &str,
    effect: &str,
    level: &str,
    role_match: Option<&str>,
    classification_match: Option<&str>,
    tag_match: Option<&str>,
    enabled: bool,
    created_by: &str,
) {
    sqlx::query(
        "INSERT INTO abac_policies (id, name, effect, level, role_match, classification_match, tag_match, enabled, created_by) \
         VALUES ($1, $1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(name)
    .bind(effect)
    .bind(level)
    .bind(role_match)
    .bind(classification_match)
    .bind(tag_match)
    .bind(enabled)
    .bind(created_by)
    .execute(pool)
    .await
    .expect("seed policy");
}

pub async fn seed_checklist(pool: &PgPool, id: &str, asset_id: &str, stig_id: &str) {
    sqlx::query("INSERT INTO checklists (id, asset_id, stig_id) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(asset_id)
        .bind(stig_id)
        .execute(pool)
        .await
        .expect("seed checklist");
}

pub fn auth(id: &str, role: &str) -> AuthUser {
    AuthUser {
        id: id.into(),
        display_name: id.into(),
        email: String::new(),
        role: role.into(),
    }
}

/// Removes the temp data dir (best effort) when dropped; hold it for the
/// test's lifetime.
pub struct StigDir(std::path::PathBuf);

impl Drop for StigDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An `AppState` over `pool` whose data dir holds a three-rule STIG named
/// [`STIG_ID`] under a unique temp directory.
pub fn app_state(pool: PgPool) -> (AppState, StigDir) {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let stigs = dir.join("stigs");
    std::fs::create_dir_all(&stigs).expect("create stig dir");
    let rules: Vec<_> = RULES.iter().map(|id| serde_json::json!({ "id": id, "title": id })).collect();
    std::fs::write(
        stigs.join(format!("{STIG_ID}.json")),
        serde_json::json!({ "id": STIG_ID, "rules": rules }).to_string(),
    )
    .expect("write stig");
    let guard = StigDir(dir.clone());
    let state = AppState {
        pool: Arc::new(pool),
        config: Arc::new(Config {
            port: 0,
            database_url: String::new(),
            data_dir: dir,
            sync_interval_hours: 100_000,
        }),
        signing: None,
    };
    (state, guard)
}
