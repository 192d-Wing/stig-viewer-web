// Thin wrapper around fetch that:
// - Resolves URLs against VITE_API_BASE_URL
// - Always sends cookies (credentials: 'include'), required for the session
//   cookie on cross-origin dev requests between :5173 and :8080
// - Throws on 401 so callers can trigger a login redirect

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080'

export class UnauthorizedError extends Error {
  constructor(message = 'unauthorized') {
    super(message)
    this.name = 'UnauthorizedError'
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

// Kick the browser into the IdP login flow and come back to the current page.
export function redirectToLogin() {
  const returnTo = window.location.href
  const q = new URLSearchParams({ return_to: returnTo })
  window.location.href = `${API_BASE_URL}/api/auth/login?${q}`
}
