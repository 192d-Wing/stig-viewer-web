//! Thin async wrapper around IndexedDB for offline STIG caching.
//!
//! Two object stores:
//!   - "meta"  keyed by string; holds { key: 'catalog', value: CatalogEntry[],
//!     cachedAt: ISO timestamp }
//!   - "stigs" keyed by STIG id; holds { id, stig, cachedAt }
//!
//! Writes are best-effort. Any IndexedDB failure (user in private mode,
//! quota exceeded, API not available) degrades gracefully: reads return
//! `None` and writes silently no-op. Callers should treat the cache as a
//! latency/offline hint, never a source of truth.

use gloo_events::EventListener;
use js_sys::{Object, Promise, Reflect};
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    EventTarget, IdbDatabase, IdbObjectStore, IdbObjectStoreParameters, IdbRequest, IdbTransactionMode,
};

use crate::util::now_iso;

const DB_NAME: &str = "stig-viewer";
const DB_VERSION: u32 = 1;
const META_STORE: &str = "meta";
const STIG_STORE: &str = "stigs";
const CATALOG_KEY: &str = "catalog";

/// The cached catalog list plus when it was stored (ISO timestamp).
#[derive(Clone, Debug, PartialEq)]
pub struct CachedCatalog<T> {
    pub list: T,
    pub cached_at: String,
}

/// A cached STIG plus when it was stored (ISO timestamp).
#[derive(Clone, Debug, PartialEq)]
pub struct CachedStig<T> {
    pub stig: T,
    pub cached_at: String,
}

/// Wait for the first of the given events on `target`. Resolves to `true`
/// for one of `ok`, `false` for one of `fail`.
///
/// The listeners are attached before the first suspension point, so calling
/// this right after creating a request / transaction cannot miss its events.
async fn settled(target: &EventTarget, ok: &[&'static str], fail: &[&'static str]) -> bool {
    let mut listeners = Vec::new();
    let promise = Promise::new(&mut |resolve, _reject| {
        for (events, outcome) in [(ok, true), (fail, false)] {
            for event in events.iter().copied() {
                let resolve = resolve.clone();
                listeners.push(EventListener::new(target, event, move |_| {
                    let _ = resolve.call1(&JsValue::NULL, &JsValue::from_bool(outcome));
                }));
            }
        }
    });
    let outcome = JsFuture::from(promise).await;
    drop(listeners);
    outcome.ok().and_then(|v| v.as_bool()).unwrap_or(false)
}

async fn open_db() -> Option<IdbDatabase> {
    let factory = web_sys::window()?.indexed_db().ok()??;
    let request = factory.open_with_u32(DB_NAME, DB_VERSION).ok()?;
    let upgrade = {
        let request = request.clone();
        EventListener::new(&request.clone(), "upgradeneeded", move |_| {
            let Some(db) = request.result().ok().and_then(|v| v.dyn_into::<IdbDatabase>().ok()) else {
                return;
            };
            for (store, key_path) in [(META_STORE, "key"), (STIG_STORE, "id")] {
                if !db.object_store_names().contains(store) {
                    let params = IdbObjectStoreParameters::new();
                    params.set_key_path(&JsValue::from_str(key_path));
                    let _ = db.create_object_store_with_optional_parameters(store, &params);
                }
            }
        })
    };
    let opened = settled(&request, &["success"], &["error"]).await;
    drop(upgrade);
    if !opened {
        return None;
    }
    request.result().ok()?.dyn_into().ok()
}

/// Run `f` against `store_name` inside one transaction and wait for it to
/// finish. Returns the result of the request `f` handed back (if any) once
/// the transaction completed; `None` on any failure or a missing row.
async fn tx(
    store_name: &str,
    mode: IdbTransactionMode,
    f: impl FnOnce(&IdbObjectStore) -> Option<IdbRequest>,
) -> Option<JsValue> {
    let db = open_db().await?;
    let result = async {
        let t = db.transaction_with_str_and_mode(store_name, mode).ok()?;
        let store = t.object_store(store_name).ok()?;
        // A throwing `f` (e.g. DataCloneError) yields no request; we still
        // wait for the transaction to wind down before closing the db.
        let request = f(&store);
        if !settled(&t, &["complete"], &["error", "abort"]).await {
            return None;
        }
        let value = request?.result().ok()?;
        (!value.is_undefined() && !value.is_null()).then_some(value)
    }
    .await;
    db.close();
    result
}

fn to_js<T: Serialize + ?Sized>(value: &T) -> Option<JsValue> {
    // Plain objects / arrays (not `Map`s) so rows match what the previous
    // JavaScript implementation stored.
    value.serialize(&serde_wasm_bindgen::Serializer::json_compatible()).ok()
}

fn row(fields: &[(&str, JsValue)]) -> JsValue {
    let obj = Object::new();
    for (key, value) in fields {
        let _ = Reflect::set(&obj, &JsValue::from_str(key), value);
    }
    let _ = Reflect::set(&obj, &JsValue::from_str("cachedAt"), &JsValue::from_str(&now_iso()));
    obj.into()
}

fn field(row: &JsValue, key: &str) -> Option<JsValue> {
    Reflect::get(row, &JsValue::from_str(key)).ok()
}

fn cached_at(row: &JsValue) -> String {
    field(row, "cachedAt").and_then(|v| v.as_string()).unwrap_or_default()
}

// ── Catalog ──────────────────────────────────────────────────────────────────

pub async fn cache_catalog<T: Serialize + ?Sized>(list: &T) {
    let Some(value) = to_js(list) else {
        return;
    };
    let row = row(&[("key", JsValue::from_str(CATALOG_KEY)), ("value", value)]);
    tx(META_STORE, IdbTransactionMode::Readwrite, |store| store.put(&row).ok()).await;
}

pub async fn read_cached_catalog<T: DeserializeOwned>() -> Option<CachedCatalog<T>> {
    let row = tx(META_STORE, IdbTransactionMode::Readonly, |store| {
        store.get(&JsValue::from_str(CATALOG_KEY)).ok()
    })
    .await?;
    let list = serde_wasm_bindgen::from_value(field(&row, "value")?).ok()?;
    Some(CachedCatalog { list, cached_at: cached_at(&row) })
}

// ── Per-STIG JSON ────────────────────────────────────────────────────────────

pub async fn cache_stig<T: Serialize + ?Sized>(id: &str, stig: &T) {
    if id.is_empty() {
        return;
    }
    let Some(value) = to_js(stig) else {
        return;
    };
    let row = row(&[("id", JsValue::from_str(id)), ("stig", value)]);
    tx(STIG_STORE, IdbTransactionMode::Readwrite, |store| store.put(&row).ok()).await;
}

pub async fn read_cached_stig<T: DeserializeOwned>(id: &str) -> Option<CachedStig<T>> {
    if id.is_empty() {
        return None;
    }
    let row = tx(STIG_STORE, IdbTransactionMode::Readonly, |store| {
        store.get(&JsValue::from_str(id)).ok()
    })
    .await?;
    let stig = serde_wasm_bindgen::from_value(field(&row, "stig")?).ok()?;
    Some(CachedStig { stig, cached_at: cached_at(&row) })
}

// ── Bulk ops ─────────────────────────────────────────────────────────────────

/// Drop everything the cache holds. Not wired to any UI yet (same as the
/// JavaScript original), hence the `allow`.
#[allow(dead_code)]
pub async fn clear_cache() {
    tx(META_STORE, IdbTransactionMode::Readwrite, |store| store.clear().ok()).await;
    tx(STIG_STORE, IdbTransactionMode::Readwrite, |store| store.clear().ok()).await;
}
