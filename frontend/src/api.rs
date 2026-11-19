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

/// Why a request made with `api_request_timed` did not complete.
#[derive(Debug, PartialEq)]
pub enum FetchFailure {
    /// No usable response: offline, DNS, CORS, connection reset.
    Network(String),
    /// The request was aborted after the timeout.
    Timeout,
    /// The request could not be built (never worth retrying).
    Build(String),
}

/// A send or body-read error is a timeout when our timer fired the abort,
/// otherwise a network failure.
fn abort_failure(timed_out: bool, msg: String) -> FetchFailure {
    if timed_out {
        FetchFailure::Timeout
    } else {
        FetchFailure::Network(msg)
    }
}

/// Shown when a checklist-set request ran out of time.
pub const TIMEOUT_MSG: &str = "The request timed out. Check your connection and try again.";

impl FetchFailure {
    /// A message fit for an error banner.
    pub fn message(&self) -> String {
        match self {
            FetchFailure::Timeout => TIMEOUT_MSG.to_string(),
            FetchFailure::Network(m) | FetchFailure::Build(m) => m.clone(),
        }
    }
}

/// Deadline for every checklist-set request, headers and body together.
pub const SET_REQUEST_TIMEOUT_MS: u32 = 15_000;
/// Save to system fans out one write per STIG, so it gets longer.
pub const SET_SAVE_TO_SYSTEM_TIMEOUT_MS: u32 = 60_000;

/// A response read to the end inside one deadline.
#[derive(Debug, Clone, PartialEq)]
pub struct TimedResponse {
    pub status: u16,
    pub retry_after: Option<u32>,
    pub body: String,
}

impl TimedResponse {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json<T: DeserializeOwned>(&self) -> Result<T, String> {
        serde_json::from_str(&self.body).map_err(js_err)
    }

    /// The body when there is one, else a generic status message.
    fn error_text(&self) -> String {
        if self.body.is_empty() {
            format!("Request failed ({})", self.status)
        } else {
            self.body.clone()
        }
    }
}

/// Request with an optional pre-serialized JSON body, aborted after
/// `timeout_ms`. The one deadline covers waiting for headers and reading the
/// body (aborting the signal also fails the body stream), so a stalled
/// connection cannot hang the caller at either step. Does not treat non-2xx
/// as an error.
pub async fn api_request_timed(
    method: &str,
    path: &str,
    json_body: Option<&str>,
    timeout_ms: u32,
) -> Result<TimedResponse, FetchFailure> {
    use std::{cell::Cell, rc::Rc};
    let ctl = web_sys::AbortController::new().map_err(|e| FetchFailure::Build(format!("{e:?}")))?;
    let timed_out = Rc::new(Cell::new(false));
    // Held until the body is read: dropping it cancels the timer.
    let _timer = {
        let (ctl, timed_out) = (ctl.clone(), timed_out.clone());
        gloo_timers::callback::Timeout::new(timeout_ms, move || {
            timed_out.set(true);
            ctl.abort();
        })
    };
    let b = builder(method, path).abort_signal(Some(&ctl.signal()));
    let req = match json_body {
        Some(body) => b
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| FetchFailure::Build(js_err(e)))?,
        None => b.build().map_err(|e| FetchFailure::Build(js_err(e)))?,
    };
    let failure = |e: gloo_net::Error| abort_failure(timed_out.get(), js_err(e));
    let res = req.send().await.map_err(failure)?;
    let status = res.status();
    let retry_after = res
        .headers()
        .get("retry-after")
        .and_then(|v| v.parse().ok());
    let body = res.text().await.map_err(failure)?;
    Ok(TimedResponse {
        status,
        retry_after,
        body,
    })
}

/// Checklist-set request parsing a JSON response, under `timeout_ms`.
/// Errors carry the response body text, or the timeout message.
pub async fn set_json<T: DeserializeOwned, B: Serialize + ?Sized>(
    method: &str,
    path: &str,
    body: Option<&B>,
    timeout_ms: u32,
) -> Result<T, String> {
    let res = set_request(method, path, body, timeout_ms).await?;
    res.json()
}

/// Like [`set_json`] for endpoints that answer 204 / an empty body.
pub async fn set_send<B: Serialize + ?Sized>(
    method: &str,
    path: &str,
    body: Option<&B>,
    timeout_ms: u32,
) -> Result<(), String> {
    set_request(method, path, body, timeout_ms)
        .await
        .map(|_| ())
}

async fn set_request<B: Serialize + ?Sized>(
    method: &str,
    path: &str,
    body: Option<&B>,
    timeout_ms: u32,
) -> Result<TimedResponse, String> {
    let json = match body {
        Some(b) => Some(serde_json::to_string(b).map_err(js_err)?),
        None => None,
    };
    let res = api_request_timed(method, path, json.as_deref(), timeout_ms)
        .await
        .map_err(|f| f.message())?;
    if res.ok() {
        Ok(res)
    } else {
        Err(res.error_text())
    }
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
        None => builder(method, path)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(js_err)?,
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

/// Raw multipart POST of a prepared form. Carries credentials like every
/// other call here. Does not treat non-2xx as an error.
pub async fn api_post_form(path: &str, form: web_sys::FormData) -> Result<Response, String> {
    builder("POST", path)
        .body(form)
        .map_err(js_err)?
        .send()
        .await
        .map_err(js_err)
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
pub async fn api_upload<T: DeserializeOwned>(
    path: &str,
    file: &web_sys::File,
) -> Result<T, String> {
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
    web_sys::Blob::new_with_buffer_source_sequence_and_options(&parts, &opts)
        .map_err(|e| format!("{e:?}"))
}

/// The filename from a `Content-Disposition` header, if any.
pub fn response_filename(res: &Response) -> Option<String> {
    let cd = res.headers().get("content-disposition")?;
    let idx = cd.find("filename=")?;
    let name = cd[idx + 9..].split(';').next()?.trim().trim_matches('"');
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_after_our_abort_is_a_timeout_otherwise_a_network_failure() {
        // The same mapping serves a stalled body read as a stalled send.
        assert_eq!(abort_failure(true, "aborted".into()), FetchFailure::Timeout);
        assert_eq!(
            abort_failure(false, "reset".into()),
            FetchFailure::Network("reset".into())
        );
    }

    #[test]
    fn timeouts_and_statuses_read_sensibly() {
        assert_eq!(FetchFailure::Timeout.message(), TIMEOUT_MSG);
        let r = |status, body: &str| TimedResponse {
            status,
            retry_after: None,
            body: body.into(),
        };
        assert!(r(204, "").ok() && !r(409, "").ok());
        assert_eq!(r(500, "").error_text(), "Request failed (500)");
        assert_eq!(r(409, "boom").error_text(), "boom");
    }
}
