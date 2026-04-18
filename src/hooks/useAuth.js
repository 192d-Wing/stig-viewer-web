import { useEffect, useState, useCallback } from 'react'
import { apiFetch, API_BASE_URL } from '../api.js'

// Auth state machine:
//   'loading'  — initial /me fetch in flight
//   'authed'   — session cookie present and valid
//   'anon'     — server requires auth but no session; show login page
//   'disabled' — server has no OIDC configured; treat as always-on single user
//
// `/api/auth/me` returns:
//   200 + body when authed
//   401          when auth is enabled but no valid session
//   204          when auth is disabled (dev open mode)

export function useAuth() {
  const [status, setStatus] = useState('loading')
  const [user, setUser] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const res = await apiFetch('/api/auth/me')
      if (res.status === 204) {
        setStatus('disabled')
        setUser(null)
        return
      }
      if (!res.ok) {
        setStatus('anon')
        setUser(null)
        return
      }
      const body = await res.json()
      setUser(body)
      setStatus('authed')
    } catch (err) {
      // UnauthorizedError or network error — treat as anonymous, not fatal
      if (err?.name !== 'UnauthorizedError') {
        console.warn('auth check failed', err)
      }
      setStatus('anon')
      setUser(null)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const logout = useCallback(async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' })
    } catch {
      // fall through — we're logging out regardless
    }
    setUser(null)
    setStatus('anon')
  }, [])

  return { status, user, refresh, logout, apiBaseUrl: API_BASE_URL }
}
