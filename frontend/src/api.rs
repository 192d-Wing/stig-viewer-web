//! Thin fetch helpers around the backend API.
//!
//! Every request carries credentials (session cookie) and, when present, the
//! `X-User-Id` header from localStorage — the test-auth bypass the E2E suite
//! and local development rely on.

use gloo_net::http::{Request, RequestBuilder, Response};
use serde::{de::DeserializeOwned, Serialize};
use web_sys::RequestCredentials;

/// Backend origin baked in at build time. `API_URL` wins; `VITE_API_URL` is
/// honoured so existing compose files and shell setups keep working.
pub const BACKEND: &str = match option_env!("API_URL") {
    Some(u) => u,
    None => match option_env!("VITE_API_URL") {
        Some(u) => u,
        None => "http://localhost:8080",
    },
};

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

pub fn user_id() -> String {
    local_storage()
        .and_then(|s| s.get_item("userId").ok().flatten())
        .unwrap_or_default()
}

fn builder(method: &str, path: &str) -> RequestBuilder {
    let url = format!("{BACKEND}{path}");
    let b = match method {
        "POST" => Request::post(&url),
        "PUT" => Request::put(&url),
        "PATCH" => Request::patch(&url),
        "DELETE" => Request::delete(&url),
        _ => Request::get(&url),
    }
    .credentials(RequestCredentials::Include);
    let uid = user_id();
    if uid.is_empty() {
        b
    } else {
        b.header("X-User-Id", &uid)
    }
}

fn js_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn error_text(res: Response) -> String {
    let status = res.status();
    let fallback = res.status_text();
    match res.text().await {
        Ok(t) if !t.is_empty() => t,
        _ if !fallback.is_empty() => fallback,
        _ => status.to_string(),
    }
}

/// Raw request without a body. Does not treat non-2xx as an error — inspect
/// `Response::ok()` / `status()` yourself (mirrors `apiFetch`).
pub async fn api_fetch(method: &str, path: &str) -> Result<Response, String> {
    builder(method, path).send().await.map_err(js_err)
}

/// Raw request with a JSON body. Does not treat non-2xx as an error.
pub async fn api_fetch_json<B: Serialize + ?Sized>(
    method: &str,
    path: &str,
    body: &B,
) -> Result<Response, String> {
    builder(method, path)
        .json(body)
        .map_err(js_err)?
        .send()
        .await
        .map_err(js_err)
}

/// GET + parse JSON. Errors as `"<status> <statusText>"` on non-2xx.
pub async fn api_get<T: DeserializeOwned>(path: &str) -> Result<T, String> {
    let res = api_fetch("GET", path).await?;
    if !res.ok() {
        return Err(format!("{} {}", res.status(), res.status_text()));
    }
    res.json::<T>().await.map_err(js_err)
}

/// POST/PUT/PATCH/DELETE with an optional JSON body, parsing a JSON response.
/// Errors carry the response body text (mirrors `apiJson`).
pub async fn api_json<T: DeserializeOwned, B: Serialize + ?Sized>(
    path: &str,
    method: &str,
    body: Option<&B>,
) -> Result<T, String> {
    let res = match body {
        Some(b) => api_fetch_json(method, path, b).await?,
        None => {
            builder(method, path)
                .header("Content-Type", "application/json")
                .send()
                .await
                .map_err(js_err)?
        }
    };
    if !res.ok() {
        return Err(error_text(res).await);
    }
    res.json::<T>().await.map_err(js_err)
}

/// Like [`api_json`] but for endpoints that answer 204 / an empty body.
pub async fn api_send<B: Serialize + ?Sized>(
    path: &str,
    method: &str,
    body: Option<&B>,
) -> Result<(), String> {
    let res = match body {
        Some(b) => api_fetch_json(method, path, b).await?,
        None => api_fetch(method, path).await?,
    };
    if !res.ok() {
        return Err(error_text(res).await);
    }
    Ok(())
}

/// Raw multipart POST of one file under the field name `file`. Does not treat
/// non-2xx as an error.
pub async fn api_upload_raw(path: &str, file: &web_sys::File) -> Result<Response, String> {
    let fd = web_sys::FormData::new().map_err(|e| format!("{e:?}"))?;
    fd.append_with_blob_and_filename("file", file, &file.name())
        .map_err(|e| format!("{e:?}"))?;
    builder("POST", path)
        .body(fd)
        .map_err(js_err)?
        .send()
        .await
        .map_err(js_err)
}

/// Multipart POST of one file, parsing a JSON response (mirrors `apiUpload`).
pub async fn api_upload<T: DeserializeOwned>(path: &str, file: &web_sys::File) -> Result<T, String> {
    let res = api_upload_raw(path, file).await?;
    if !res.ok() {
        return Err(error_text(res).await);
    }
    res.json::<T>().await.map_err(js_err)
}

/// Read a response body into a Blob (for authenticated downloads), keeping
/// the server's Content-Type.
pub async fn response_blob(res: &Response) -> Result<web_sys::Blob, String> {
    let bytes = res.binary().await.map_err(js_err)?;
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes.as_slice()).buffer());
    let opts = web_sys::BlobPropertyBag::new();
    if let Some(ct) = res.headers().get("content-type") {
        opts.set_type(&ct);
    }
    web_sys::Blob::new_with_buffer_source_sequence_and_options(&parts, &opts).map_err(|e| format!("{e:?}"))
}

/// The filename from a `Content-Disposition` header, if any.
pub fn response_filename(res: &Response) -> Option<String> {
    let cd = res.headers().get("content-disposition")?;
    let idx = cd.find("filename=")?;
    let name = cd[idx + 9..].split(';').next()?.trim().trim_matches('"');
    (!name.is_empty()).then(|| name.to_string())
}
