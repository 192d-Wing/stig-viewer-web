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
