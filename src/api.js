// Thin wrapper around fetch that:
// - Resolves URLs against VITE_API_BASE_URL
// - Always sends cookies (credentials: 'include'), required for the session
//   cookie on cross-origin dev requests between :5173 and :8080
// - Throws on 401 so callers can trigger a login redirect
// - Exposes structured errors from the backend's {error:{code,message,details}}
//   body via ApiError; callers show `.message` and can branch on `.code`

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080'

export class UnauthorizedError extends Error {
  constructor(message = 'unauthorized') {
    super(message)
    this.name = 'UnauthorizedError'
  }
}

export class ApiError extends Error {
  constructor({ status, code, message, details }) {
    super(message || `Request failed (${status})`)
    this.name = 'ApiError'
    this.status = status
    this.code = code || 'unknown'
    this.details = details || null
  }
}

export async function apiFetch(path, init = {}) {
  const url = path.startsWith('http') ? path : `${API_BASE_URL}${path}`
  const res = await fetch(url, {
    credentials: 'include',
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init.headers || {}),
    },
  })
  if (res.status === 401) throw new UnauthorizedError()
  return res
}

// Parse a failed response as the backend's structured error body.
// Falls back to {code: http_<status>, message: statusText} when the body
// isn't JSON (e.g. a proxy returned an HTML error page).
export async function readApiError(res) {
  let body
  try {
    body = await res.json()
  } catch {
    return new ApiError({
      status: res.status,
      code: `http_${res.status}`,
      message: res.statusText || `Request failed (${res.status})`,
    })
  }
  const err = body && body.error ? body.error : {}
  return new ApiError({
    status: res.status,
    code: err.code,
    message: err.message,
    details: err.details,
  })
}

// Convenience: await a fetch, return JSON on 2xx, throw ApiError otherwise.
export async function apiJson(path, init = {}) {
  const res = await apiFetch(path, init)
  if (!res.ok) throw await readApiError(res)
  return res.json()
}

// Kick the browser into the IdP login flow and come back to the current page.
export function redirectToLogin() {
  const returnTo = window.location.href
  const q = new URLSearchParams({ return_to: returnTo })
  window.location.href = `${API_BASE_URL}/api/auth/login?${q}`
}
