//! Shared helpers for integration tests.
//!
//! Each `#[sqlx::test]` receives a fresh `PgPool` pointed at a clean database
//! with migrations applied. [`spawn_app`] binds the Axum router on a random
//! local port and returns a base URL that `reqwest` can hit, along with a
//! tempdir that backs `DATA_DIR` for uploads.
//!
//! Auth is left unconfigured so the server runs in "dev open mode" — every
//! request is treated as the synthetic admin user defined by the extractor.

use std::{net::SocketAddr, sync::Arc};

use sqlx::PgPool;
use stig_viewer_backend::{build_app, config::Config, AppState};
use tempfile::TempDir;

pub struct TestApp {
    pub base_url: String,
    pub pool: Arc<PgPool>,
    /// Backs the uploads data directory; dropped when the test ends.
    pub _data_dir: TempDir,
    /// Cancels the serving task when the TestApp is dropped.
    pub _server: tokio::task::JoinHandle<()>,
}

pub async fn spawn_app(pool: PgPool) -> TestApp {
    let data_dir = tempfile::tempdir().expect("tempdir");
    tokio::fs::create_dir_all(data_dir.path().join("stigs"))
        .await
        .expect("mkdir stigs");

    let config = Arc::new(Config {
        port: 0,
        database_url: String::new(),
        data_dir: data_dir.path().to_path_buf(),
        sync_interval_hours: 24,
        max_upload_bytes: 50 * 1024 * 1024,
        max_library_bytes: 500 * 1024 * 1024,
        // 0 disables the rate limiter so tests aren't flaky.
        upload_rate_per_min: 0,
    });

    let pool = Arc::new(pool);
    let state = AppState {
        pool: pool.clone(),
        config,
        auth: None,
        sources: None,
    };

    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    TestApp {
        base_url: format!("http://{addr}"),
        pool,
        _data_dir: data_dir,
        _server: server,
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        self._server.abort();
    }
}
