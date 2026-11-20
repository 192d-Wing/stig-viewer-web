use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::PgPool;
use std::{path::Path, sync::Arc};
use tracing::{error, info, warn};

use crate::{
    config::{Config, StigSource},
    db::{upsert_catalog, CatalogEntry},
    parser::{extract_xccdf_from_zip, parse_xccdf},
};

/// Reject a source whose id is not a valid new STIG id, before any I/O.
fn validate_source(source: &StigSource) -> Result<()> {
    if !crate::stig_id::is_valid_new(&source.id) {
        anyhow::bail!(
            "STIG id {:?} is invalid (1-{} lower-case ASCII letters, digits or hyphens); skipped",
            source.id.chars().take(64).collect::<String>(),
            crate::stig_id::MAX_BYTES
        );
    }
    Ok(())
}

/// What happened to one source in a sync pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Downloaded, parsed and indexed (the file may or may not have changed).
    Synced,
    /// DISA answered 404 or 410: the URL in stig-sources.toml is out of date.
    StaleUrl,
}

/// Totals for one sync pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncSummary {
    pub synced: usize,
    pub stale: usize,
    pub errors: usize,
}

impl SyncSummary {
    /// One-line description for the scheduler log.
    pub fn describe(&self) -> String {
        format!(
            "synced {}, {} stale URL(s), {} error(s)",
            self.synced, self.stale, self.errors
        )
    }
}

/// A 404 or 410 means the manifest URL has gone stale (DISA publishes a new
/// file name per release); every other non-success status is a real error.
fn is_stale_status(status: u16) -> bool {
    matches!(status, 404 | 410)
}

/// Map a file read to the previous contents: `NotFound` is `None`, any other
/// error is propagated.
fn existing_bytes(read: std::io::Result<Vec<u8>>) -> std::io::Result<Option<Vec<u8>>> {
    match read {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// True when the file on disk already holds exactly the new bytes.
fn is_unchanged(existing: Option<&[u8]>, new: &[u8]) -> bool {
    existing == Some(new)
}

/// Largest STIG ZIP download accepted from DISA (matches the upload limit).
const MAX_DISA_DOWNLOAD_BYTES: usize = 500 * 1024 * 1024;

/// A download stopped by the size cap. A typed error so the caller can audit it.
#[derive(Debug)]
struct DownloadTooLarge {
    limit: usize,
    /// The `Content-Length` DISA declared, when the pre-check tripped.
    declared: Option<u64>,
}

impl std::fmt::Display for DownloadTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "response body is larger than {} bytes", self.limit)
    }
}

impl std::error::Error for DownloadTooLarge {}

/// The audit event for a download stopped by the size cap: no acting user, no
/// URL. Shared by the DISA path and the test-only `system-audit-event` route
/// so the route writes the production event shape.
pub(crate) fn download_too_large_event(
    stig_id: &str,
    limit: usize,
    declared: Option<u64>,
) -> crate::db_audit::NewSystemEvent<'_> {
    crate::db_audit::NewSystemEvent {
        action: "catalog.sync",
        outcome: "rejected",
        stig_id: Some(stig_id),
        detail: serde_json::json!({
            "reasonCode": "download_too_large",
            "limitBytes": limit,
            "declaredBytes": declared,
        }),
    }
}

/// Read a response body, refusing more than `limit` bytes. A declared
/// `Content-Length` over the limit is refused before any body is read; a
/// body without one (or lying about it) is cut off as it streams.
async fn read_capped_body(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let declared = resp.content_length();
    read_capped_chunks(declared, limit, &mut resp).await
}

/// Where body chunks come from; a trait so the cap logic is testable.
trait ChunkSource {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>>;
}

impl ChunkSource for reqwest::Response {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let chunk = self.chunk().await.context("Failed to read response body")?;
        Ok(chunk.map(|b| b.to_vec()))
    }
}

async fn read_capped_chunks(
    declared: Option<u64>,
    limit: usize,
    source: &mut impl ChunkSource,
) -> Result<Vec<u8>> {
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(DownloadTooLarge { limit, declared }.into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = source.next_chunk().await? {
        if body.len() + chunk.len() > limit {
            return Err(DownloadTooLarge {
                limit,
                declared: None,
            }
            .into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Download, parse, and index one STIG from DISA.
async fn sync_one(
    source: &StigSource,
    client: &reqwest::Client,
    pool: &PgPool,
    data_dir: &Path,
) -> Result<Outcome> {
    sync_one_with(source, client, pool, data_dir, MAX_DISA_DOWNLOAD_BYTES).await
}

/// [`sync_one`] with an explicit download cap (a seam for tests).
async fn sync_one_with(
    source: &StigSource,
    client: &reqwest::Client,
    pool: &PgPool,
    data_dir: &Path,
    limit: usize,
) -> Result<Outcome> {
    validate_source(source)?;
    info!("Syncing STIG '{}' from {}", source.id, source.url);

    // 1. Download ZIP
    let resp = client
        .get(&source.url)
        .send()
        .await
        .context("HTTP request failed")?;

    if is_stale_status(resp.status().as_u16()) {
        warn!(
            "source '{}' URL not found (HTTP {}); update stig-sources.toml",
            source.id,
            resp.status().as_u16()
        );
        return Ok(Outcome::StaleUrl);
    }
    if !resp.status().is_success() {
        anyhow::bail!("DISA returned HTTP {}", resp.status());
    }

    let zip_bytes = match read_capped_body(resp, limit).await {
        Ok(b) => b,
        Err(e) => {
            // A download stopped by the cap has no acting user: audit it as a
            // system event (no URL in the detail).
            if let Some(t) = e.downcast_ref::<DownloadTooLarge>() {
                warn!(
                    target: "audit",
                    action = "catalog.sync",
                    reason_code = "download_too_large",
                    stig_id = %source.id,
                    "DISA download refused: {t}"
                );
                crate::db_audit::record_system_or_log(
                    pool,
                    download_too_large_event(&source.id, t.limit, t.declared),
                )
                .await;
            }
            return Err(e);
        }
    };

    // 2. Extract XCCDF XML from ZIP (handles double-zipped STIGs)
    // Both steps are CPU-bound, so they run off the async workers.
    let stig = tokio::task::spawn_blocking(move || -> Result<_> {
        let xccdf =
            extract_xccdf_from_zip(&zip_bytes).context("Failed to extract XCCDF from ZIP")?;
        // 3. Parse XCCDF → StigData
        parse_xccdf(&xccdf).context("Failed to parse XCCDF")
    })
    .await
    .context("ZIP extraction task failed")??;

    // 4. Write JSON file
    let stigs_dir = data_dir.join("stigs");
    tokio::fs::create_dir_all(&stigs_dir).await?;
    let json_path = stigs_dir.join(format!("{}.json", source.id));

    let json_str = serde_json::to_string(&stig)?;

    // 4a. Identical bytes: nothing to write and nothing to archive. (The
    //     catalog row is still upserted below so a reset database re-indexes.)
    // Only a missing file counts as "no previous version"; any other read
    // error must not lead to archiving being skipped and the file replaced.
    let existing = existing_bytes(tokio::fs::read(&json_path).await)
        .with_context(|| format!("Cannot read existing {}", json_path.display()))?;
    let unchanged = is_unchanged(existing.as_deref(), json_str.as_bytes());

    // 4b. If a previous JSON already exists for this STIG, archive it
    //     under stigs/archive/ keyed by the OLD version + release so the
    //     diff endpoint can compare current vs prior. We look up the
    //     pre-sync catalog row to capture the about-to-be-replaced
    //     metadata.
    if !unchanged && existing.is_some() {
        if let Err(e) = archive_previous_catalog(pool, data_dir, &source.id, &json_path).await {
            // Archive failures are non-fatal — log and continue so a
            // disk hiccup or unique-constraint race doesn't stop the
            // actual sync from updating the live catalog.
            warn!(
                "Failed to archive previous version of '{}': {e:#}",
                source.id
            );
        }
    }

    if unchanged {
        info!("'{}' unchanged; not rewritten", source.id);
    } else {
        tokio::fs::write(&json_path, json_str.as_bytes()).await?;
        info!("Wrote '{}'", json_path.display());
    }

    // 5. Upsert catalog row in Postgres
    let entry = CatalogEntry {
        id: source.id.clone(),
        // Prefer title parsed from XCCDF; fall back to the manifest title
        title: if stig.title.is_empty() {
            source.title.clone()
        } else {
            stig.title.clone()
        },
        category: source.category.clone(),
        version: stig.version.clone(),
        release_info: stig.release_info.clone(),
        rule_count: stig.rules.len() as i32,
        json_path: json_path.to_string_lossy().into_owned(),
        last_updated: Utc::now(),
    };
    upsert_catalog(pool, &entry)
        .await
        .context("Failed to upsert catalog entry")?;

    info!(
        "Synced '{}': {} rules → {}",
        source.id,
        stig.rules.len(),
        json_path.display()
    );
    Ok(Outcome::Synced)
}

/// Copy `${data_dir}/stigs/{id}.json` to
/// `${data_dir}/stigs/archive/{id}-v{version}-r{release_safe}.json`
/// and insert a `catalog_archive` row pointing at that file. Uses the
/// stigs_catalog row's CURRENT values (which are about to be replaced)
/// as the archived version/release. Safe to call when no catalog row
/// exists yet — early-returns with Ok.
async fn archive_previous_catalog(
    pool: &PgPool,
    data_dir: &Path,
    stig_id: &str,
    current_json: &Path,
) -> Result<()> {
    // Fetch the about-to-be-replaced version + release from the catalog.
    // If no row exists yet (first ever sync) there's nothing to archive.
    let row: Option<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT version, release_info FROM stigs_catalog WHERE id = $1",
    )
    .bind(stig_id)
    .fetch_optional(pool)
    .await?;

    let Some((old_version, old_release)) = row else {
        return Ok(());
    };

    let archive_dir = data_dir.join("stigs").join("archive");
    tokio::fs::create_dir_all(&archive_dir).await?;

    let archive_name = archive_file_name(stig_id, &old_version, &old_release);
    let archive_abs = archive_dir.join(&archive_name);

    // Copy the file regardless — if a previous archive run already
    // wrote it we'll either overwrite identical bytes (no-op) or pick
    // up corruption from a half-written prior copy and replace it. The
    // DB insert below is the source of truth for whether we're done.
    tokio::fs::copy(current_json, &archive_abs).await?;

    // Relative path under data_dir so the row is portable across
    // deployments / mount points. matches the convention used by the
    // existing stigs_catalog.json_path field.
    let rel_path = format!("stigs/archive/{archive_name}");

    let res = sqlx::query(
        r#"
        INSERT INTO catalog_archive (stig_id, version, release_info, json_path)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (stig_id, version, release_info) DO NOTHING
        "#,
    )
    .bind(stig_id)
    .bind(&old_version)
    .bind(&old_release)
    .bind(&rel_path)
    .execute(pool)
    .await?;

    if res.rows_affected() == 0 {
        info!(
            "Archive already exists for '{}' v{} ({}) — skipped",
            stig_id, old_version, old_release
        );
    } else {
        info!(
            "Archived previous '{}' v{} ({}) → {}",
            stig_id,
            old_version,
            old_release,
            archive_abs.display()
        );
    }
    Ok(())
}

/// Archive file name for a replaced STIG version. The sanitised version and
/// release are readable but lossy (`1.2` and `1-2` agree), so a hash of the
/// raw pair keeps distinct versions from overwriting each other.
pub(crate) fn archive_file_name(stig_id: &str, version: &str, release_info: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(version.as_bytes());
    h.update([0u8]);
    h.update(release_info.as_bytes());
    let digest = h.finalize();
    let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!(
        "{stig_id}-v{}-r{}-{short}.json",
        sanitize_release(version),
        sanitize_release(release_info)
    )
}

/// Replace whitespace and other filesystem-unfriendly characters in a
/// release_info string so it can be embedded in an archive filename.
///
/// `"Release: 4 Benchmark Date: 09 Apr 2026"` → `"Release-4-Benchmark-Date-09-Apr-2026"`.
fn sanitize_release(release_info: &str) -> String {
    let mut out = String::with_capacity(release_info.len());
    let mut prev_dash = false;
    for c in release_info.chars() {
        if c.is_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// Run one full sync pass across all STIG sources.
pub async fn run_sync(
    config: &Arc<Config>,
    sources: &Arc<Vec<StigSource>>,
    pool: &PgPool,
) -> Result<SyncSummary> {
    let client = reqwest::Client::builder()
        .user_agent("stig-viewer-backend/0.1")
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut summary = SyncSummary::default();
    for source in sources.as_ref() {
        match sync_one(source, &client, pool, &config.data_dir).await {
            Ok(Outcome::Synced) => summary.synced += 1,
            Ok(Outcome::StaleUrl) => summary.stale += 1,
            Err(e) => {
                error!("Failed to sync '{}': {e:#}", source.id);
                summary.errors += 1;
            }
        }
    }

    if summary.errors == 0 && summary.stale == 0 {
        info!("Sync complete — {}", summary.describe());
    } else {
        warn!(
            "Sync finished: {} (of {} sources)",
            summary.describe(),
            sources.len()
        );
    }
    Ok(summary)
}

#[cfg(test)]
mod id_tests {
    use super::*;

    fn src(id: &str) -> StigSource {
        StigSource {
            id: id.into(),
            title: "t".into(),
            category: "c".into(),
            url: "u".into(),
        }
    }

    #[test]
    fn archive_names_differ_for_colliding_versions() {
        let a = archive_file_name("x", "1.2", "R 1");
        let b = archive_file_name("x", "1-2", "R 1");
        let c = archive_file_name("x", "1.2", "R-1");
        assert!(a.starts_with("x-v1-2-rR-1-") && a.ends_with(".json"));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, archive_file_name("x", "1.2", "R 1"));
    }

    #[test]
    fn only_404_and_410_are_stale() {
        assert!(is_stale_status(404));
        assert!(is_stale_status(410));
        for other in [200, 301, 403, 429, 500, 502, 503] {
            assert!(!is_stale_status(other), "{other}");
        }
    }

    #[test]
    fn summary_counts_stale_separately() {
        let s = SyncSummary {
            synced: 5,
            stale: 2,
            errors: 1,
        };
        assert_eq!(s.describe(), "synced 5, 2 stale URL(s), 1 error(s)");
    }

    #[test]
    fn only_not_found_means_no_previous_file() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            existing_bytes(Ok(b"x".to_vec())).unwrap(),
            Some(b"x".to_vec())
        );
        assert_eq!(
            existing_bytes(Err(Error::from(ErrorKind::NotFound))).unwrap(),
            None
        );
        let e = existing_bytes(Err(Error::from(ErrorKind::PermissionDenied))).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn unchanged_only_when_bytes_equal() {
        assert!(is_unchanged(Some(b"one"), b"one"));
        assert!(!is_unchanged(Some(b"one"), b"two"));
        assert!(!is_unchanged(None, b"one"), "a missing file is a change");
        assert!(!is_unchanged(None, b""));
    }

    #[test]
    fn validate_source_rejects_bad_ids() {
        for bad in ["../x", "a.b", "a b", "", "Upper", "é"] {
            assert!(validate_source(&src(bad)).is_err(), "{bad}");
        }
        assert!(validate_source(&src("windows-10")).is_ok());
        assert!(validate_source(&src("a")).is_ok());
    }

    use sqlx::PgPool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve one HTTP response: `head` (status line + headers) then `body`.
    /// Returns the URL. The connection closes after the body.
    async fn serve_once(head: String, body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.shutdown().await;
        });
        url
    }

    async fn fetch(head: &str, body: Vec<u8>, limit: usize) -> Result<Vec<u8>> {
        let url = serve_once(head.to_string(), body).await;
        let resp = reqwest::Client::new().get(url).send().await.unwrap();
        read_capped_body(resp, limit).await
    }

    #[tokio::test]
    async fn an_over_cap_content_length_is_refused_without_reading_the_body() {
        // Headers promise 100 bytes, none follow: only a pre-check can refuse.
        let e = fetch(
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
            vec![],
            10,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("larger than 10 bytes"), "{e}");
        let t = e.downcast_ref::<DownloadTooLarge>().expect("typed error");
        assert_eq!((t.limit, t.declared), (10, Some(100)));
    }

    #[tokio::test]
    async fn a_streamed_body_over_the_cap_is_cut_off_without_a_content_length() {
        let e = fetch(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            vec![b'x'; 50],
            10,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("larger than 10 bytes"), "{e}");
        let t = e.downcast_ref::<DownloadTooLarge>().expect("typed error");
        assert_eq!((t.limit, t.declared), (10, None));
    }

    #[tokio::test]
    async fn a_chunked_body_over_the_cap_is_cut_off() {
        let mut body = b"32\r\n".to_vec();
        body.extend(vec![b'x'; 50]);
        body.extend(b"\r\n0\r\n\r\n");
        let e = fetch(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            body,
            10,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("larger than 10 bytes"), "{e}");
    }

    #[tokio::test]
    async fn an_under_cap_body_comes_back_intact() {
        let body: Vec<u8> = (0..200u8).collect();
        let got = fetch(
            "HTTP/1.1 200 OK\r\nContent-Length: 200\r\nConnection: close\r\n\r\n",
            body.clone(),
            200,
        )
        .await
        .unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn a_lying_content_length_cannot_beat_the_streaming_cap() {
        // Declares 5 bytes (under the cap) but the chunk source yields 50.
        struct Fake(std::vec::IntoIter<Vec<u8>>);
        impl ChunkSource for Fake {
            async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
                Ok(self.0.next())
            }
        }
        let mut src = Fake(vec![vec![b'x'; 25], vec![b'x'; 25]].into_iter());
        let e = read_capped_chunks(Some(5), 10, &mut src).await.unwrap_err();
        assert!(e.to_string().contains("larger than 10 bytes"), "{e}");
    }

    // ── Database-backed: a capped download is audited as a system event ──

    fn source_for(id: &str, url: String) -> StigSource {
        StigSource {
            id: id.into(),
            title: "t".into(),
            category: "Linux".into(),
            url,
        }
    }

    async fn sync_rows(
        pool: &PgPool,
    ) -> Vec<(
        Option<String>,
        Option<String>,
        Option<String>,
        serde_json::Value,
    )> {
        sqlx::query_as(
            "SELECT user_id, user_role, stig_id, detail FROM audit_events WHERE action = 'catalog.sync'",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_download_over_the_cap_is_audited_as_a_system_event(pool: PgPool) {
        let (state, _dir) = crate::test_fixtures::app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n".into(),
            vec![b'x'; 100],
        )
        .await;
        let e = sync_one_with(
            &source_for("big-src", url),
            &reqwest::Client::new(),
            &pool,
            &data_dir,
            10,
        )
        .await
        .unwrap_err();
        assert!(e.downcast_ref::<DownloadTooLarge>().is_some(), "{e:#}");
        let rows = sync_rows(&pool).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        let (user, role, stig, detail) = &rows[0];
        assert_eq!(user, &None);
        assert_eq!(role.as_deref(), Some("system"));
        assert_eq!(stig.as_deref(), Some("big-src"));
        assert_eq!(detail["reasonCode"], "download_too_large");
        assert_eq!(detail["limitBytes"], 10);
        assert_eq!(detail["declaredBytes"], 100);
        assert!(!detail.to_string().contains("127.0.0.1"), "{detail}");
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn a_streamed_download_over_the_cap_is_audited_without_a_declared_size(pool: PgPool) {
        let (state, _dir) = crate::test_fixtures::app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".into(),
            vec![b'x'; 50],
        )
        .await;
        let e = sync_one_with(
            &source_for("stream-src", url),
            &reqwest::Client::new(),
            &pool,
            &data_dir,
            10,
        )
        .await
        .unwrap_err();
        assert!(e.downcast_ref::<DownloadTooLarge>().is_some(), "{e:#}");
        let rows = sync_rows(&pool).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, None);
        assert_eq!(rows[0].2.as_deref(), Some("stream-src"));
        assert_eq!(rows[0].3["limitBytes"], 10);
        assert!(rows[0].3["declaredBytes"].is_null(), "{}", rows[0].3);
    }

    #[sqlx::test]
    #[ignore = "needs Postgres (DATABASE_URL)"]
    async fn other_sync_failures_write_no_audit_row(pool: PgPool) {
        let (state, _dir) = crate::test_fixtures::app_state(pool.clone());
        let data_dir = state.config.data_dir.clone();
        // Under the cap but not a ZIP: fails later, must not be audited.
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".into(),
            b"hello".to_vec(),
        )
        .await;
        let e = sync_one_with(
            &source_for("small-src", url),
            &reqwest::Client::new(),
            &pool,
            &data_dir,
            10,
        )
        .await
        .unwrap_err();
        assert!(e.downcast_ref::<DownloadTooLarge>().is_none(), "{e:#}");
        assert!(sync_rows(&pool).await.is_empty());
    }
}
