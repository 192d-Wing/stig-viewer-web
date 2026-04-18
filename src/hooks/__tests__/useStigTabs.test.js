import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useStigTabs } from '../useStigTabs.js'

const SAMPLE_STIG = {
  title: 'Sample',
  version: '1',
  releaseInfo: 'Release: 1',
  rules: [
    {
      id: 'R-1',
      stigId: 'V-1',
      title: 't',
      severity: 'CAT II',
      status: 'not_reviewed',
      findingDetails: '',
      comments: '',
    },
    {
      id: 'R-2',
      stigId: 'V-2',
      title: 't',
      severity: 'CAT II',
      status: 'not_reviewed',
      findingDetails: '',
      comments: '',
    },
  ],
}

function fakeRes({ status = 200, ok, body }) {
  return {
    status,
    ok: ok ?? (status >= 200 && status < 300),
    json: async () => body,
  }
}

describe('useStigTabs workspace sync', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('merges a fetched workspace into the loaded STIG', async () => {
    globalThis.fetch.mockResolvedValueOnce(
      fakeRes({
        status: 200,
        body: {
          stigId: 'windows-11',
          assetInfo: { hostname: 'host-1', ip: '', mac: '', fqdn: '' },
          ruleOverrides: {
            'R-1': { status: 'not_a_finding', findingDetails: 'ok', comments: '' },
          },
          updatedAt: '2025-01-01T00:00:00Z',
        },
      }),
    )
    const { result } = renderHook(() => useStigTabs())
    await act(async () => {
      await result.current.addStigFromBackend(SAMPLE_STIG, 'windows-11')
    })
    await waitFor(() => expect(result.current.tabs).toHaveLength(1))
    const tab = result.current.tabs[0]
    expect(tab.catalogId).toBe('windows-11')
    expect(tab.assetInfo.hostname).toBe('host-1')
    expect(tab.stig.rules[0].status).toBe('not_a_finding')
    expect(tab.stig.rules[0].findingDetails).toBe('ok')
    // Untouched rule keeps its default.
    expect(tab.stig.rules[1].status).toBe('not_reviewed')
  })

  it('treats a 404 workspace as "nothing saved yet"', async () => {
    globalThis.fetch.mockResolvedValueOnce(fakeRes({ status: 404, body: {} }))
    const { result } = renderHook(() => useStigTabs())
    await act(async () => {
      await result.current.addStigFromBackend(SAMPLE_STIG, 'windows-11')
    })
    await waitFor(() => expect(result.current.tabs).toHaveLength(1))
    expect(result.current.tabs[0].stig.rules[0].status).toBe('not_reviewed')
  })

  it('debounces a PUT when a rule status changes', async () => {
    globalThis.fetch
      // initial workspace fetch → no saved state
      .mockResolvedValueOnce(fakeRes({ status: 404, body: {} }))
      // the eventual PUT
      .mockResolvedValueOnce(fakeRes({ status: 200, body: {} }))

    const { result } = renderHook(() => useStigTabs())
    await act(async () => {
      await result.current.addStigFromBackend(SAMPLE_STIG, 'windows-11')
    })
    const tabId = result.current.tabs[0].id

    await act(async () => {
      result.current.updateRule(tabId, 'R-1', { status: 'open' })
    })

    // No save fires before the debounce window elapses.
    const callsBeforeDebounce = globalThis.fetch.mock.calls.length
    expect(callsBeforeDebounce).toBe(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1100)
    })

    await waitFor(() => {
      expect(globalThis.fetch.mock.calls.length).toBe(2)
    })
    const [putUrl, putInit] = globalThis.fetch.mock.calls[1]
    expect(putUrl).toMatch(/\/api\/workspaces\/windows-11$/)
    expect(putInit.method).toBe('PUT')
    const payload = JSON.parse(putInit.body)
    expect(payload.ruleOverrides['R-1'].status).toBe('open')
    // Unchanged default-status rule is omitted.
    expect(payload.ruleOverrides['R-2']).toBeUndefined()
  })

  it('undoes and redoes a rule status change', async () => {
    globalThis.fetch.mockResolvedValueOnce(fakeRes({ status: 404, body: {} }))

    const { result } = renderHook(() => useStigTabs())
    await act(async () => {
      await result.current.addStigFromBackend(SAMPLE_STIG, 'windows-11')
    })
    const tabId = result.current.tabs[0].id
    expect(result.current.canUndo).toBe(false)

    await act(async () => {
      result.current.updateRule(tabId, 'R-1', { status: 'open' })
    })
    expect(result.current.tabs[0].stig.rules[0].status).toBe('open')
    expect(result.current.canUndo).toBe(true)
    expect(result.current.canRedo).toBe(false)

    await act(async () => result.current.undo())
    expect(result.current.tabs[0].stig.rules[0].status).toBe('not_reviewed')
    expect(result.current.canUndo).toBe(false)
    expect(result.current.canRedo).toBe(true)

    await act(async () => result.current.redo())
    expect(result.current.tabs[0].stig.rules[0].status).toBe('open')
    expect(result.current.canUndo).toBe(true)
    expect(result.current.canRedo).toBe(false)
  })

  it('records setAllStatus as a single entry and undoes to the prior mix', async () => {
    globalThis.fetch.mockResolvedValueOnce(fakeRes({ status: 404, body: {} }))

    const { result } = renderHook(() => useStigTabs())
    await act(async () => {
      await result.current.addStigFromBackend(SAMPLE_STIG, 'windows-11')
    })
    const tabId = result.current.tabs[0].id

    await act(async () => result.current.updateRule(tabId, 'R-1', { status: 'open' }))
    await act(async () => result.current.setAllStatus(tabId, 'not_applicable'))

    expect(result.current.tabs[0].stig.rules.every((r) => r.status === 'not_applicable')).toBe(true)

    await act(async () => result.current.undo())
    // Restored to the mix: R-1 open, R-2 not_reviewed.
    expect(result.current.tabs[0].stig.rules[0].status).toBe('open')
    expect(result.current.tabs[0].stig.rules[1].status).toBe('not_reviewed')
  })

  it('does not persist tabs added from local files', async () => {
    const { result } = renderHook(() => useStigTabs())

    // Fake a file object with a .text() method that returns our sample XML.
    const file = {
      name: 'sample.xml',
      text: async () =>
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">' +
        '<title>X</title><version>1</version></Benchmark>',
    }

    await act(async () => {
      await result.current.addTabs([file])
    })

    expect(result.current.tabs).toHaveLength(1)
    expect(result.current.tabs[0].catalogId).toBeNull()
    // No workspace fetch or PUT should have occurred.
    expect(globalThis.fetch).not.toHaveBeenCalled()
  })
})
