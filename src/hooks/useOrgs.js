import { useCallback, useEffect, useState } from 'react'
import { apiFetch, UnauthorizedError } from '../api.js'
import { notify } from './useNotifications.js'

// Drives the TopNavigation org switcher. Fetches /api/orgs/me on mount to
// get { active, memberships }, and exposes switchTo(slug) that POSTs to
// /api/orgs/switch. After a successful switch we reload the page so every
// open tab, the catalog, and any cached data refetch fresh — there's too
// much in-memory state keyed by the previous org to bother invalidating
// surgically.

export function useOrgs() {
  const [active, setActive] = useState(null)
  const [memberships, setMemberships] = useState([])
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const res = await apiFetch('/api/orgs/me')
      if (res.ok) {
        const body = await res.json()
        setActive(body.active ?? null)
        setMemberships(Array.isArray(body.memberships) ? body.memberships : [])
      }
    } catch (err) {
      // 401 is handled by useAuth's redirect; anything else is logged and
      // leaves the switcher in its initial empty state.
      if (!(err instanceof UnauthorizedError)) {
        console.warn('org fetch failed', err)
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const switchTo = useCallback(
    async (slug) => {
      if (slug === active?.slug) return
      try {
        const res = await apiFetch('/api/orgs/switch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ slug }),
        })
        if (!res.ok) {
          let message = `Switch failed (${res.status})`
          try {
            const body = await res.json()
            if (body?.error?.message) message = body.error.message
          } catch {
            /* keep default */
          }
          throw new Error(message)
        }
        notify.info(`Switched to ${slug}`)
        window.location.reload()
      } catch (err) {
        if (err instanceof UnauthorizedError) return
        notify.error(`Failed to switch organisation: ${err.message}`)
      }
    },
    [active?.slug],
  )

  return { active, memberships, loading, switchTo, refresh }
}
