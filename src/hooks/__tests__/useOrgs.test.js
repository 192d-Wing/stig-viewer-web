import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useOrgs } from '../useOrgs.js'

function res({ status = 200, ok, body }) {
  return {
    status,
    ok: ok ?? (status >= 200 && status < 300),
    json: async () => body,
  }
}

describe('useOrgs', () => {
  // Preserve the real location so we can restore it; we swap a stub in
  // for tests that observe reload().
  const originalLocation = window.location

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    window.location = originalLocation
  })

  it('loads active org + memberships from /api/orgs/me on mount', async () => {
    globalThis.fetch.mockResolvedValueOnce(
      res({
        body: {
          active: { id: 1, slug: 'default', name: 'Default' },
          memberships: [
            { id: 1, slug: 'default', name: 'Default' },
            { id: 2, slug: 'acme', name: 'Acme' },
          ],
        },
      }),
    )
    const { result } = renderHook(() => useOrgs())
    expect(result.current.loading).toBe(true)
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.active.slug).toBe('default')
    expect(result.current.memberships).toHaveLength(2)
  })

  it('leaves state empty when /me fails with a network error', async () => {
    globalThis.fetch.mockRejectedValueOnce(new TypeError('network down'))
    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { result } = renderHook(() => useOrgs())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.active).toBeNull()
    expect(result.current.memberships).toEqual([])
    consoleWarn.mockRestore()
  })

  it('switchTo POSTs /api/orgs/switch then reloads the page', async () => {
    globalThis.fetch
      // initial /me
      .mockResolvedValueOnce(
        res({
          body: {
            active: { id: 1, slug: 'default', name: 'Default' },
            memberships: [
              { id: 1, slug: 'default', name: 'Default' },
              { id: 2, slug: 'acme', name: 'Acme' },
            ],
          },
        }),
      )
      // the switch
      .mockResolvedValueOnce(res({ body: { id: 2, slug: 'acme', name: 'Acme' } }))

    // Replace location with a stub that captures reload().
    const reload = vi.fn()
    delete window.location
    window.location = { ...originalLocation, reload, href: 'http://localhost/' }

    const { result } = renderHook(() => useOrgs())
    await waitFor(() => expect(result.current.loading).toBe(false))

    await act(async () => {
      await result.current.switchTo('acme')
    })

    const [, switchCall] = globalThis.fetch.mock.calls
    expect(switchCall[0]).toMatch(/\/api\/orgs\/switch$/)
    expect(switchCall[1]).toMatchObject({ method: 'POST' })
    expect(JSON.parse(switchCall[1].body)).toEqual({ slug: 'acme' })
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('switchTo is a no-op when already on the target slug', async () => {
    globalThis.fetch.mockResolvedValueOnce(
      res({
        body: {
          active: { id: 1, slug: 'default', name: 'Default' },
          memberships: [{ id: 1, slug: 'default', name: 'Default' }],
        },
      }),
    )
    const { result } = renderHook(() => useOrgs())
    await waitFor(() => expect(result.current.loading).toBe(false))

    await act(async () => {
      await result.current.switchTo('default')
    })

    // Only the initial /me call happened; no switch POST.
    expect(globalThis.fetch).toHaveBeenCalledTimes(1)
  })
})
