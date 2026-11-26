//! In-memory static file server for the release frontend (`STIG_STATIC_DIR`).
//!
//! The directory is walked once at startup into a map keyed by `/relative/path`.
//! A request is answered by exact key lookup, so no request-derived filesystem
//! path exists (no traversal, no symlink following). The frontend routes on
//! `location.pathname`, so any miss that is not under a backend prefix
//! (`/api/`, `/auth/`) returns `index.html`. The handler is a router fallback:
//! it is public and sits outside the auth stack by design, like `/api/health`.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use axum::{
    body::{Body, Bytes},
    http::{header, HeaderValue, Method, Response, StatusCode},
};

/// Loader bounds: a Trunk release bundle is a handful of files.
const MAX_DEPTH: usize = 4;
const MAX_FILES: usize = 2000;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Path roots owned by the backend; a miss at or under them is a plain 404.
const BACKEND_ROOTS: [&str; 2] = ["/api", "/auth"];

fn is_backend_path(path: &str) -> bool {
    BACKEND_ROOTS.iter().any(|r| {
        path.strip_prefix(r)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Loader bounds, parameters so tests can use small ones.
#[derive(Clone, Copy)]
struct Limits {
    depth: usize,
    files: usize,
    bytes: u64,
}

const LIMITS: Limits = Limits {
    depth: MAX_DEPTH,
    files: MAX_FILES,
    bytes: MAX_TOTAL_BYTES,
};

const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
const CACHE_REVALIDATE: &str = "no-cache";
const CACHE_DEFAULT: &str = "max-age=3600";

#[derive(Debug)]
struct Asset {
    body: Bytes,
    content_type: &'static str,
    cache_control: &'static str,
}

/// All static files, held in memory.
#[derive(Debug)]
pub struct StaticSite {
    assets: HashMap<String, Asset>,
    /// Send `Strict-Transport-Security` (production only).
    hsts: bool,
}

/// Fixed extension table; anything else is `application/octet-stream`.
fn content_type_for(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()) {
        Some(e) => match e.as_str() {
            "html" => "text/html; charset=utf-8",
            "js" | "mjs" => "text/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "wasm" => "application/wasm",
            "woff2" => "font/woff2",
            "png" => "image/png",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "json" => "application/json",
            _ => "application/octet-stream",
        },
        None => "application/octet-stream",
    }
}

/// Trunk hashes asset names as `<stem>-<16 hex>.<ext>`.
fn is_hashed_name(name: &str) -> bool {
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    match stem.rsplit_once('-') {
        Some((_, h)) => h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

fn cache_control_for(key: &str) -> &'static str {
    let name = key.rsplit('/').next().unwrap_or(key);
    if name == "index.html" || name == "boot.js" {
        CACHE_REVALIDATE
    } else if is_hashed_name(name) {
        CACHE_IMMUTABLE
    } else {
        CACHE_DEFAULT
    }
}

struct Totals {
    files: usize,
    bytes: u64,
}

fn walk(
    dir: &Path,
    prefix: &str,
    depth: usize,
    lim: Limits,
    totals: &mut Totals,
    out: &mut HashMap<String, Asset>,
) -> Result<()> {
    if depth > lim.depth {
        bail!("static directory nests deeper than {} levels", lim.depth);
    }
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        // Never follow symlinks; skip anything that is not a plain file or dir.
        let meta = fs::symlink_metadata(entry.path())?;
        let key = format!("{prefix}/{name}");
        if meta.is_dir() {
            walk(&entry.path(), &key, depth + 1, lim, totals, out)?;
        } else if meta.is_file() {
            totals.files += 1;
            totals.bytes += meta.len();
            if totals.files > lim.files {
                bail!("static directory has more than {} files", lim.files);
            }
            if totals.bytes > lim.bytes {
                bail!("static directory is larger than {} bytes", lim.bytes);
            }
            let body = fs::read(entry.path()).with_context(|| format!("read {key}"))?;
            out.insert(
                key.clone(),
                Asset {
                    body: Bytes::from(body),
                    content_type: content_type_for(&name),
                    cache_control: cache_control_for(&key),
                },
            );
        }
    }
    Ok(())
}

impl StaticSite {
    /// Walk `dir` once. Fails when `index.html` is missing or a bound is hit.
    /// `hsts` adds `Strict-Transport-Security` to every response.
    pub fn load(dir: &Path, hsts: bool) -> Result<Self> {
        Self::load_with(dir, hsts, LIMITS)
    }

    fn load_with(dir: &Path, hsts: bool, lim: Limits) -> Result<Self> {
        let mut assets = HashMap::new();
        let mut totals = Totals { files: 0, bytes: 0 };
        walk(dir, "", 0, lim, &mut totals, &mut assets)?;
        if !assets.contains_key("/index.html") {
            bail!("{} has no index.html", dir.display());
        }
        Ok(Self { assets, hsts })
    }

    /// Answer one request. Only GET and HEAD are served.
    pub fn respond(&self, method: &Method, path: &str) -> Response<Body> {
        // Backend-owned paths first, so `POST /api/nope` is 404, not 405.
        if is_backend_path(path) && !self.assets.contains_key(path) {
            return self.plain(StatusCode::NOT_FOUND);
        }
        let head = method == Method::HEAD;
        if method != Method::GET && !head {
            let mut res = self.plain(StatusCode::METHOD_NOT_ALLOWED);
            res.headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return res;
        }
        let key = if path == "/" { "/index.html" } else { path };
        let asset = match self.assets.get(key) {
            Some(a) => a,
            None => match self.assets.get("/index.html") {
                Some(a) => a,
                None => return self.plain(StatusCode::NOT_FOUND),
            },
        };
        let mut res = Response::new(if head {
            Body::empty()
        } else {
            Body::from(asset.body.clone())
        });
        let h = res.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(asset.content_type),
        );
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(asset.cache_control),
        );
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(asset.body.len()));
        security_headers(res, self.hsts)
    }

    fn plain(&self, status: StatusCode) -> Response<Body> {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = status;
        security_headers(res, self.hsts)
    }
}

/// Headers on every static response, including 404/405. `frame-ancestors`
/// cannot be set by the `<meta>` CSP, so it is enforced here.
fn security_headers(mut res: Response<Body>, hsts: bool) -> Response<Body> {
    let h = res.headers_mut();
    if hsts {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "svw-static-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn write(&self, rel: &str, body: &[u8]) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn site() -> (StaticSite, TmpDir) {
        let d = TmpDir::new();
        d.write("index.html", b"<html>index</html>");
        d.write("boot.js", b"boot");
        d.write("app-0123456789abcdef.wasm", b"\0asm");
        d.write("assets/logo.png", b"png");
        (StaticSite::load(&d.0, false).unwrap(), d)
    }

    fn get(s: &StaticSite, path: &str) -> Response<Body> {
        s.respond(&Method::GET, path)
    }

    #[test]
    fn load_requires_index_html() {
        let d = TmpDir::new();
        d.write("a.js", b"x");
        assert!(StaticSite::load(&d.0, false).is_err());
    }

    #[test]
    fn load_skips_symlinks() {
        let d = TmpDir::new();
        d.write("index.html", b"i");
        let outside = TmpDir::new();
        outside.write("secret.txt", b"s");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.0.join("secret.txt"), d.0.join("link.txt")).unwrap();
            std::os::unix::fs::symlink(&outside.0, d.0.join("linkdir")).unwrap();
        }
        let s = StaticSite::load(&d.0, false).unwrap();
        assert!(!s.assets.contains_key("/link.txt"));
        assert!(!s.assets.keys().any(|k| k.starts_with("/linkdir")));
    }

    #[test]
    fn load_enforces_depth_bound() {
        let d = TmpDir::new();
        d.write("index.html", b"i");
        d.write("a/b/c/d/e/f.js", b"x");
        assert!(StaticSite::load(&d.0, false).is_err());
        let ok = TmpDir::new();
        ok.write("index.html", b"i");
        ok.write("a/b/c/d/f.js", b"x");
        assert!(StaticSite::load(&ok.0, false).is_ok());
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type_for("x.wasm"), "application/wasm");
        assert_eq!(content_type_for("x.HTML"), "text/html; charset=utf-8");
        assert_eq!(content_type_for("x.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type_for("x.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("x.woff2"), "font/woff2");
        assert_eq!(content_type_for("x.svg"), "image/svg+xml");
        assert_eq!(content_type_for("x.bin"), "application/octet-stream");
        assert_eq!(content_type_for("noext"), "application/octet-stream");
    }

    #[test]
    fn cache_classes() {
        assert_eq!(cache_control_for("/index.html"), CACHE_REVALIDATE);
        assert_eq!(cache_control_for("/boot.js"), CACHE_REVALIDATE);
        assert_eq!(
            cache_control_for("/app-0123456789abcdef.wasm"),
            CACHE_IMMUTABLE
        );
        assert_eq!(cache_control_for("/assets/logo.png"), CACHE_DEFAULT);
        assert_eq!(cache_control_for("/app-xyz.wasm"), CACHE_DEFAULT);
    }

    #[tokio::test]
    async fn serves_assets_index_and_404s() {
        let (s, _d) = site();
        let r = get(&s, "/app-0123456789abcdef.wasm");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/wasm");
        assert_eq!(r.headers()[header::CACHE_CONTROL], CACHE_IMMUTABLE);
        assert_eq!(r.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(
            r.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'none'"
        );
        for p in ["/", "/some/deep/link", "/index.html"] {
            let r = get(&s, p);
            assert_eq!(r.status(), StatusCode::OK, "{p}");
            assert_eq!(r.headers()[header::CACHE_CONTROL], CACHE_REVALIDATE);
        }
        for p in ["/api/nope", "/auth/nope", "/api/", "/api", "/auth"] {
            assert_eq!(get(&s, p).status(), StatusCode::NOT_FOUND, "{p}");
            assert_eq!(get(&s, p).headers()[header::X_FRAME_OPTIONS], "DENY", "{p}");
        }
        // Similar-looking non-backend paths are SPA routes.
        assert_eq!(get(&s, "/apix").status(), StatusCode::OK);
        assert_eq!(
            s.respond(&Method::POST, "/api/nope").status(),
            StatusCode::NOT_FOUND
        );
        // Traversal text is just a key that misses.
        assert_eq!(get(&s, "/../etc/passwd").status(), StatusCode::OK);
        let r = s.respond(&Method::POST, "/");
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(r.headers()[header::X_FRAME_OPTIONS], "DENY");
        assert!(r.headers().get(header::STRICT_TRANSPORT_SECURITY).is_none());
        let h = s.respond(&Method::HEAD, "/");
        assert_eq!(h.status(), StatusCode::OK);
        assert_eq!(h.headers()[header::CONTENT_LENGTH], "18");
        let body = axum::body::to_bytes(h.into_body(), 1024).await.unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn hsts_only_when_enabled() {
        let d = TmpDir::new();
        d.write("index.html", b"i");
        let on = StaticSite::load(&d.0, true).unwrap();
        for (m, p) in [
            (Method::GET, "/"),
            (Method::GET, "/api/x"),
            (Method::POST, "/"),
        ] {
            assert_eq!(
                on.respond(&m, p).headers()[header::STRICT_TRANSPORT_SECURITY],
                "max-age=31536000; includeSubDomains"
            );
        }
        let off = StaticSite::load(&d.0, false).unwrap();
        assert!(off
            .respond(&Method::GET, "/")
            .headers()
            .get(header::STRICT_TRANSPORT_SECURITY)
            .is_none());
    }

    #[test]
    fn load_enforces_file_count_and_size_bounds() {
        let d = TmpDir::new();
        d.write("index.html", b"i");
        d.write("a.js", b"x");
        d.write("b.js", b"x");
        let lim = Limits {
            depth: 4,
            files: 2,
            bytes: 1000,
        };
        assert!(StaticSite::load_with(&d.0, false, lim).is_err());
        let lim = Limits {
            depth: 4,
            files: 3,
            bytes: 1000,
        };
        assert!(StaticSite::load_with(&d.0, false, lim).is_ok());
        let lim = Limits {
            depth: 4,
            files: 10,
            bytes: 2,
        };
        assert!(StaticSite::load_with(&d.0, false, lim).is_err());
    }
}
