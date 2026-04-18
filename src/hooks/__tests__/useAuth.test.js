import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useAuth } from '../useAuth.js'

// Helper for building a fetch Response-like object.
function res({ status = 200, ok, body }) {
  return {
    status,
    ok: ok ?? (status >= 200 && status < 300),
    json: async () => body,
  }
}

describe('useAuth', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('transitions to authed on a 200 /me response', async () => {
    globalThis.fetch.mockResolvedValueOnce(
      res({
        status: 200,
        body: { sub: 'u1', email: 'u1@x', role: 'admin', exp: 0 },
      }),
    )
    const { result } = renderHook(() => useAuth())
    expect(result.current.status).toBe('loading')
    await waitFor(() => expect(result.current.status).toBe('authed'))
    expect(result.current.user).toMatchObject({ sub: 'u1', role: 'admin' })
  })

  it('transitions to disabled when /me returns 204', async () => {
    globalThis.fetch.mockResolvedValueOnce(res({ status: 204, body: undefined }))
    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current.status).toBe('disabled'))
    expect(result.current.user).toBeNull()
  })

  it('transitions to anon on 401', async () => {
    globalThis.fetch.mockResolvedValueOnce(res({ status: 401, body: {} }))
    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current.status).toBe('anon'))
    expect(result.current.user).toBeNull()
  })

  it('transitions to anon on network error', async () => {
    globalThis.fetch.mockRejectedValueOnce(new TypeError('network down'))
    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current.status).toBe('anon'))
  })

  it('logout() posts /api/auth/logout and flips to anon', async () => {
    globalThis.fetch
      // initial /me
      .mockResolvedValueOnce(
        res({ status: 200, body: { sub: 'u1', role: 'admin', exp: 0 } }),
      )
      // logout POST
      .mockResolvedValueOnce(res({ status: 204, body: undefined }))

    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current.status).toBe('authed'))

    await act(async () => {
      await result.current.logout()
    })

    expect(result.current.status).toBe('anon')
    expect(result.current.user).toBeNull()
    // Second call should be the logout POST
    const [, logoutCall] = globalThis.fetch.mock.calls
    expect(logoutCall[0]).toMatch(/\/api\/auth\/logout$/)
    expect(logoutCall[1]).toMatchObject({ method: 'POST' })
  })
})
