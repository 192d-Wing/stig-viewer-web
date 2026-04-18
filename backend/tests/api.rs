//! HTTP-level integration tests for the backend API.
//!
//! Each test receives a fresh `PgPool` via `sqlx::test`, spawns the real
//! Axum router against a random local port in "dev open mode" (no OIDC),
//! and drives it with `reqwest`. The full stack is exercised: migrations,
//! routing, middleware, handlers, database, and audit log writes.
//!
//! Requires a reachable Postgres. `sqlx::test` reads `DATABASE_URL` and
//! creates a fresh database per test. See README for the CI setup.

mod common;

use std::io::Write;

use reqwest::StatusCode;
use sqlx::PgPool;

use common::spawn_app;

/// Build a minimal DISA-shaped ZIP containing a `*_xccdf.xml` entry.
fn minimal_stig_zip(title: &str, version: &str, rule_id: &str) -> Vec<u8> {
    let xccdf = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
  <title>{title}</title>
  <description>Integration test benchmark.</description>
  <version>{version}</version>
  <Group id="V-TEST-1">
    <Rule id="{rule_id}" severity="medium">
      <title>Test rule</title>
      <description>desc</description>
      <fixtext>fix</fixtext>
      <check system="x"><check-content>check</check-content></check>
    </Rule>
  </Group>
</Benchmark>"#
    );

    let mut buf = Vec::new();
    let cursor = std::io::Cursor::new(&mut buf);
    let mut zip = zip::ZipWriter::new(cursor);
    let options: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("U_TEST_STIG_xccdf.xml", options).unwrap();
    zip.write_all(xccdf.as_bytes()).unwrap();
    zip.finish().unwrap();
    buf
}

#[sqlx::test(migrations = "./migrations")]
async fn health_returns_ok(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/health", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["stig_count"], 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn catalog_returns_empty_list_when_no_stigs(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/catalog", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_unknown_stig_returns_structured_not_found(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/stigs/nope", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn get_stig_with_bad_id_returns_bad_request(pool: PgPool) {
    let app = spawn_app(pool).await;
    // "../" would allow path traversal if validation regressed.
    let res = reqwest::get(format!("{}/api/stigs/..", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "bad_request");
}

#[sqlx::test(migrations = "./migrations")]
async fn upload_then_fetch_catalog_and_stig(pool: PgPool) {
    let app = spawn_app(pool).await;
    let zip = minimal_stig_zip("Windows 11 Test STIG", "1", "SV-1000r1_rule");

    let form = reqwest::multipart::Form::new()
        .part(
            "file",
            reqwest::multipart::Part::bytes(zip)
                .file_name("U_TEST_STIG.zip")
                .mime_str("application/zip")
                .unwrap(),
        )
        .text("id", "windows-11-test")
        .text("category", "Windows");

    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/api/upload", app.base_url))
        .multipart(form)
        .send()
        .await
        .expect("upload");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "body: {}",
        res.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["id"], "windows-11-test");
    assert_eq!(body["ruleCount"], 1);

    // Catalog now lists the uploaded STIG.
    let catalog: serde_json::Value = reqwest::get(format!("{}/api/catalog", app.base_url))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = catalog.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], "windows-11-test");
    assert_eq!(items[0]["category"], "Windows");

    // Fetching the STIG JSON returns the parsed payload.
    let stig: serde_json::Value =
        reqwest::get(format!("{}/api/stigs/windows-11-test", app.base_url))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(stig["title"], "Windows 11 Test STIG");
    assert_eq!(stig["rules"].as_array().unwrap().len(), 1);

    // Audit log has a row for the upload under the dev-open synthetic admin.
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'upload.stig' AND resource = $1",
    )
    .bind("windows-11-test")
    .fetch_one(app.pool.as_ref())
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn upload_with_invalid_id_returns_bad_request(pool: PgPool) {
    let app = spawn_app(pool).await;
    let zip = minimal_stig_zip("x", "1", "SV-1");

    let form = reqwest::multipart::Form::new()
        .part(
            "file",
            reqwest::multipart::Part::bytes(zip)
                .file_name("U_TEST_STIG.zip")
                .mime_str("application/zip")
                .unwrap(),
        )
        .text("id", "has spaces")
        .text("category", "Windows");

    let res = reqwest::Client::new()
        .post(format!("{}/api/upload", app.base_url))
        .multipart(form)
        .send()
        .await
        .expect("upload");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "bad_request");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("alphanumeric"));
}

#[sqlx::test(migrations = "./migrations")]
async fn workspace_404_before_first_put(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/workspaces/windows-11", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn workspace_put_then_get_round_trips(pool: PgPool) {
    let app = spawn_app(pool).await;
    let client = reqwest::Client::new();

    let payload = serde_json::json!({
        "assetInfo": { "hostname": "host-1", "ip": "10.0.0.5" },
        "ruleOverrides": {
            "SV-1000r1_rule": {
                "status": "not_a_finding",
                "findingDetails": "verified",
                "comments": ""
            }
        }
    });

    let res = client
        .put(format!("{}/api/workspaces/windows-11", app.base_url))
        .json(&payload)
        .send()
        .await
        .expect("put");
    assert_eq!(res.status(), StatusCode::OK);
    let stored: serde_json::Value = res.json().await.unwrap();
    assert_eq!(stored["stigId"], "windows-11");
    assert_eq!(stored["assetInfo"]["hostname"], "host-1");
    assert_eq!(
        stored["ruleOverrides"]["SV-1000r1_rule"]["status"],
        "not_a_finding"
    );

    let res = reqwest::get(format!("{}/api/workspaces/windows-11", app.base_url))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let fetched: serde_json::Value = res.json().await.unwrap();
    assert_eq!(fetched["assetInfo"]["ip"], "10.0.0.5");
    assert_eq!(
        fetched["ruleOverrides"]["SV-1000r1_rule"]["findingDetails"],
        "verified"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn workspace_put_updates_existing_row(pool: PgPool) {
    let app = spawn_app(pool).await;
    let client = reqwest::Client::new();

    let url = format!("{}/api/workspaces/windows-11", app.base_url);
    client
        .put(&url)
        .json(&serde_json::json!({
            "assetInfo": { "hostname": "first" },
            "ruleOverrides": {}
        }))
        .send()
        .await
        .unwrap();

    let res = client
        .put(&url)
        .json(&serde_json::json!({
            "assetInfo": { "hostname": "second" },
            "ruleOverrides": { "R-1": { "status": "open" } }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let fetched: serde_json::Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
    assert_eq!(fetched["assetInfo"]["hostname"], "second");
    assert_eq!(fetched["ruleOverrides"]["R-1"]["status"], "open");

    // Exactly one row for this (user, stig).
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM workspaces")
        .fetch_one(app.pool.as_ref())
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn workspace_put_rejects_non_object_payloads(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::Client::new()
        .put(format!("{}/api/workspaces/windows-11", app.base_url))
        .json(&serde_json::json!({
            "assetInfo": "not an object",
            "ruleOverrides": {}
        }))
        .send()
        .await
        .expect("put");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "bad_request");
}

#[sqlx::test(migrations = "./migrations")]
async fn workspace_rejects_bad_stig_id(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/workspaces/bad..id", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn request_id_header_is_echoed_when_supplied(pool: PgPool) {
    let app = spawn_app(pool).await;
    let client = reqwest::Client::new();
    let supplied = "11111111-2222-3333-4444-555555555555";
    let res = client
        .get(format!("{}/api/health", app.base_url))
        .header("x-request-id", supplied)
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some(supplied),
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn request_id_header_is_generated_when_absent(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/health", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    let id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    // UUID v4 canonical form: 8-4-4-4-12 hex chars.
    assert_eq!(id.len(), 36, "expected a uuid, got {id:?}");
    assert_eq!(id.matches('-').count(), 4);
}

#[sqlx::test(migrations = "./migrations")]
async fn metrics_endpoint_exposes_request_counter(pool: PgPool) {
    let app = spawn_app(pool).await;
    // Generate some traffic first.
    for _ in 0..3 {
        reqwest::get(format!("{}/api/health", app.base_url))
            .await
            .unwrap();
    }
    let body = reqwest::get(format!("{}/metrics", app.base_url))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("http_requests_total"));
    assert!(body.contains("http_request_duration_seconds"));
    assert!(
        body.contains("path=\"/api/health\""),
        "metrics body missing per-path label: {body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn livez_always_returns_ok(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/livez", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn readyz_is_ok_when_db_is_reachable(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = reqwest::get(format!("{}/api/readyz", app.base_url))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ready");
}

#[sqlx::test(migrations = "./migrations")]
async fn sync_endpoint_returns_500_when_sources_unconfigured(pool: PgPool) {
    // The test harness leaves `sources: None`, which the endpoint must
    // surface as a structured error rather than panic.
    let app = spawn_app(pool).await;
    let res = reqwest::Client::new()
        .post(format!("{}/api/sync", app.base_url))
        .send()
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["error"]["code"], "internal_error");
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_endpoint_returns_uploaded_events(pool: PgPool) {
    let app = spawn_app(pool).await;
    let zip = minimal_stig_zip("Audit Me", "1", "SV-1");
    let form = reqwest::multipart::Form::new()
        .part(
            "file",
            reqwest::multipart::Part::bytes(zip)
                .file_name("U_TEST_STIG.zip")
                .mime_str("application/zip")
                .unwrap(),
        )
        .text("id", "audit-me")
        .text("category", "Windows");

    let client = reqwest::Client::new();
    client
        .post(format!("{}/api/upload", app.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    let res = client
        .get(format!("{}/api/audit", app.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let events: serde_json::Value = res.json().await.unwrap();
    let arr = events.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["action"], "upload.stig");
    assert_eq!(arr[0]["resource"], "audit-me");
    assert_eq!(arr[0]["actorRole"], "admin");
}
