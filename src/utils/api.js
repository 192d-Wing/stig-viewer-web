const BACKEND = import.meta.env.VITE_API_URL || 'http://localhost:8080'

export { BACKEND }

/**
 * Fetch wrapper that adds the X-User-Id header from localStorage.
 * Drop-in replacement for window.fetch for all draft/auth API calls.
 */
export async function apiFetch(path, opts = {}) {
  const userId = localStorage.getItem('userId') || ''
  const headers = new Headers(opts.headers)
  if (userId) headers.set('X-User-Id', userId)

  const res = await fetch(`${BACKEND}${path}`, { ...opts, headers })
  return res
}

/** Convenience: GET JSON */
export async function apiGet(path) {
  const res = await apiFetch(path)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

/** Convenience: POST/PUT/DELETE JSON */
export async function apiJson(path, method, body) {
  const res = await apiFetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body != null ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(text || `${res.status}`)
  }
  return res.json()
}
