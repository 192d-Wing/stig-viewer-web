//! Small browser helpers shared across components.

use wasm_bindgen::{JsCast, JsValue};

pub use wasm_bindgen_futures::spawn_local;

pub fn window() -> web_sys::Window {
    web_sys::window().expect("window")
}

pub fn document() -> web_sys::Document {
    window().document().expect("document")
}

/// `Date.now()`
pub fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// `new Date().toISOString()`
pub fn now_iso() -> String {
    js_sys::Date::new_0().to_iso_string().into()
}

/// Parse anything `new Date(x)` accepts into epoch milliseconds (NaN if invalid).
pub fn parse_date_ms(s: &str) -> f64 {
    js_sys::Date::new(&JsValue::from_str(s)).get_time()
}

/// `new Date(x).toLocaleString()`
pub fn to_locale_string(s: &str) -> String {
    js_sys::Date::new(&JsValue::from_str(s))
        .to_locale_string("default", &JsValue::UNDEFINED)
        .into()
}

/// `new Date(x).toLocaleDateString()`
pub fn to_locale_date_string(s: &str) -> String {
    js_sys::Date::new(&JsValue::from_str(s))
        .to_locale_date_string("default", &JsValue::UNDEFINED)
        .into()
}

/// `new Date(ms).toLocaleDateString()`
pub fn ms_to_locale_date_string(ms: f64) -> String {
    js_sys::Date::new(&JsValue::from_f64(ms))
        .to_locale_date_string("default", &JsValue::UNDEFINED)
        .into()
}

/// `encodeURIComponent`
pub fn encode_uri_component(s: &str) -> String {
    js_sys::encode_uri_component(s).into()
}

/// Trigger a browser download of an in-memory Blob.
///
/// The anchor is attached to the document for the click and the object URL is
/// revoked a second later: revoking synchronously can cancel the download in
/// some browsers.
pub fn download_blob(blob: &web_sys::Blob, filename: &str) {
    let Ok(url) = web_sys::Url::create_object_url_with_blob(blob) else {
        return;
    };
    let doc = document();
    if let (Ok(el), Some(body)) = (doc.create_element("a"), doc.body()) {
        let a: web_sys::HtmlAnchorElement = el.unchecked_into();
        a.set_href(&url);
        a.set_download(filename);
        let _ = body.append_child(&a);
        a.click();
        a.remove();
    }
    gloo_timers::callback::Timeout::new(1_000, move || {
        let _ = web_sys::Url::revoke_object_url(&url);
    })
    .forget();
}

/// Trigger a browser download of text content with the given MIME type.
pub fn download_text(text: &str, mime: &str, filename: &str) {
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from_str(text));
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type(mime);
    if let Ok(blob) = web_sys::Blob::new_with_str_sequence_and_options(&parts, &opts) {
        download_blob(&blob, filename);
    }
}

/// Read a `File` as UTF-8 text (`file.text()`).
pub async fn file_text(file: &web_sys::File) -> Result<String, String> {
    let v = wasm_bindgen_futures::JsFuture::from(file.text())
        .await
        .map_err(|e| format!("{e:?}"))?;
    Ok(v.as_string().unwrap_or_default())
}

/// Collect a `FileList` into a Vec.
pub fn file_list_to_vec(list: Option<web_sys::FileList>) -> Vec<web_sys::File> {
    let mut out = Vec::new();
    if let Some(list) = list {
        for i in 0..list.length() {
            if let Some(f) = list.get(i) {
                out.push(f);
            }
        }
    }
    out
}

/// `navigator.clipboard.writeText` — resolves to whether the write succeeded.
pub async fn copy_to_clipboard(text: &str) -> bool {
    let clip = window().navigator().clipboard();
    wasm_bindgen_futures::JsFuture::from(clip.write_text(text))
        .await
        .is_ok()
}

/// `window.confirm`
pub fn confirm(msg: &str) -> bool {
    window().confirm_with_message(msg).unwrap_or(false)
}

/// Current `location.search` as (key, value) lookups.
pub fn url_param(key: &str) -> Option<String> {
    let search = window().location().search().ok()?;
    web_sys::UrlSearchParams::new_with_str(&search)
        .ok()?
        .get(key)
}

pub fn console_error(msg: &str) {
    web_sys::console::error_1(&JsValue::from_str(msg));
}

/// Value of the `<input>` / `<textarea>` / `<select>` an event fired on.
pub fn event_value(e: &web_sys::Event) -> String {
    let Some(t) = e.target() else {
        return String::new();
    };
    if let Some(i) = t.dyn_ref::<web_sys::HtmlInputElement>() {
        i.value()
    } else if let Some(i) = t.dyn_ref::<web_sys::HtmlTextAreaElement>() {
        i.value()
    } else if let Some(i) = t.dyn_ref::<web_sys::HtmlSelectElement>() {
        i.value()
    } else {
        String::new()
    }
}

/// `checked` state of the checkbox/radio an event fired on.
pub fn event_checked(e: &web_sys::Event) -> bool {
    e.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|i| i.checked())
        .unwrap_or(false)
}

/// Rows of a result alert's issue list: the first `cap` `(rule id, text)`
/// pairs plus how many more were left out. Rows whose text is `None` are
/// not issues and are skipped.
pub fn issue_lines<'a>(
    rows: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
    cap: usize,
) -> (Vec<(String, String)>, usize) {
    let mut issues = rows
        .into_iter()
        .filter_map(|(id, text)| text.map(|t| (id, t)));
    let lines: Vec<(String, String)> = issues
        .by_ref()
        .take(cap)
        .map(|(id, t)| (id.to_string(), t.to_string()))
        .collect();
    let more = issues.count();
    (lines, more)
}

#[cfg(test)]
mod tests {
    use super::issue_lines;

    #[test]
    fn issue_lines_skips_rows_without_text() {
        let (lines, more) = issue_lines([("a", Some("x")), ("b", None), ("c", Some("z"))], 10);
        assert_eq!(
            lines,
            [
                ("a".to_string(), "x".to_string()),
                ("c".to_string(), "z".to_string())
            ]
        );
        assert_eq!(more, 0);
    }

    #[test]
    fn issue_lines_caps_and_counts_the_rest() {
        let ids: Vec<String> = (0..13).map(|i| format!("r{i}")).collect();
        let (lines, more) = issue_lines(ids.iter().map(|i| (i.as_str(), Some("e"))), 10);
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[9].0, "r9");
        assert_eq!(more, 3);
        let (lines, more) = issue_lines(ids.iter().take(10).map(|i| (i.as_str(), Some("e"))), 10);
        assert_eq!((lines.len(), more), (10, 0));
    }

    #[test]
    fn issue_lines_zero_cap_counts_everything() {
        let (lines, more) = issue_lines([("a", Some("x")), ("b", None), ("c", Some("z"))], 0);
        assert!(lines.is_empty());
        assert_eq!(more, 2);
    }

    #[test]
    fn issue_lines_empty() {
        let (lines, more) = issue_lines(std::iter::empty(), 10);
        assert!(lines.is_empty());
        assert_eq!(more, 0);
    }
}
