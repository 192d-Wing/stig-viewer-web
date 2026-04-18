// Thin promise-based wrapper around IndexedDB for offline STIG caching.
//
// Two object stores:
//   - "meta"  keyed by string; holds { key: 'catalog', value: CatalogEntry[],
//                                       cachedAt: ISO timestamp }
//   - "stigs" keyed by STIG id; holds { id, stig, cachedAt }
//
// Writes are best-effort. Any IndexedDB failure (user in private mode,
// quota exceeded, API not available) degrades gracefully: reads return
// `null` and writes silently no-op. Callers should treat the cache as a
// latency/offline hint, never a source of truth.

const DB_NAME = 'stig-viewer'
const DB_VERSION = 1
const META_STORE = 'meta'
const STIG_STORE = 'stigs'
const CATALOG_KEY = 'catalog'

function hasIDB() {
  return typeof indexedDB !== 'undefined'
}

function openDb() {
  return new Promise((resolve, reject) => {
    if (!hasIDB()) {
      reject(new Error('IndexedDB not available'))
      return
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE, { keyPath: 'key' })
      }
      if (!db.objectStoreNames.contains(STIG_STORE)) {
        db.createObjectStore(STIG_STORE, { keyPath: 'id' })
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error ?? new Error('open failed'))
  })
}

async function tx(storeName, mode, fn) {
  let db
  try {
    db = await openDb()
  } catch {
    return null
  }
  return new Promise((resolve) => {
    let result = null
    const t = db.transaction(storeName, mode)
    const store = t.objectStore(storeName)
    try {
      result = fn(store)
    } catch {
      // Fall through to oncomplete / onerror.
    }
    t.oncomplete = () => {
      db.close()
      resolve(result)
    }
    t.onerror = () => {
      db.close()
      resolve(null)
    }
    t.onabort = () => {
      db.close()
      resolve(null)
    }
  })
}

function promiseFromRequest(request) {
  return new Promise((resolve) => {
    request.onsuccess = () => resolve(request.result ?? null)
    request.onerror = () => resolve(null)
  })
}

// ── Catalog ──────────────────────────────────────────────────────────────────

export async function cacheCatalog(list) {
  await tx(META_STORE, 'readwrite', (store) => {
    store.put({ key: CATALOG_KEY, value: list, cachedAt: new Date().toISOString() })
  })
}

export async function readCachedCatalog() {
  const result = await tx(META_STORE, 'readonly', (store) => {
    return promiseFromRequest(store.get(CATALOG_KEY))
  })
  // `result` is the promise we returned from `fn`; await it separately.
  const row = await (result ?? Promise.resolve(null))
  if (!row) return null
  return { list: row.value, cachedAt: row.cachedAt }
}

// ── Per-STIG JSON ────────────────────────────────────────────────────────────

export async function cacheStig(id, stig) {
  if (!id) return
  await tx(STIG_STORE, 'readwrite', (store) => {
    store.put({ id, stig, cachedAt: new Date().toISOString() })
  })
}

export async function readCachedStig(id) {
  if (!id) return null
  const result = await tx(STIG_STORE, 'readonly', (store) => {
    return promiseFromRequest(store.get(id))
  })
  const row = await (result ?? Promise.resolve(null))
  if (!row) return null
  return { stig: row.stig, cachedAt: row.cachedAt }
}

// ── Bulk ops ─────────────────────────────────────────────────────────────────

export async function clearCache() {
  await tx(META_STORE, 'readwrite', (store) => store.clear())
  await tx(STIG_STORE, 'readwrite', (store) => store.clear())
}
