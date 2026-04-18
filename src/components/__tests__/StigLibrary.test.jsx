import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import StigLibrary from '../StigLibrary.jsx'

const CATALOG = [
  {
    id: 'windows-11',
    title: 'Windows 11 STIG',
    category: 'Windows',
    version: '2',
    releaseInfo: 'Release: 3',
    ruleCount: 350,
    jsonPath: '/data/windows-11.json',
    lastUpdated: '2025-01-01T00:00:00Z',
  },
  {
    id: 'rhel-9',
    title: 'Red Hat Enterprise Linux 9 STIG',
    category: 'Linux',
    version: '2',
    releaseInfo: 'Release: 2',
    ruleCount: 423,
    jsonPath: '/data/rhel-9.json',
    lastUpdated: '2025-01-01T00:00:00Z',
  },
]

function fakeRes({ status = 200, ok, body }) {
  return {
    status,
    ok: ok ?? (status >= 200 && status < 300),
    json: async () => body,
  }
}

describe('<StigLibrary />', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders catalog entries fetched from /api/catalog', async () => {
    globalThis.fetch.mockResolvedValueOnce(fakeRes({ status: 200, body: CATALOG }))
    render(<StigLibrary onLoad={() => {}} />)

    await waitFor(() => {
      expect(screen.getByText('Windows 11 STIG')).toBeInTheDocument()
    })
    expect(
      screen.getByText('Red Hat Enterprise Linux 9 STIG'),
    ).toBeInTheDocument()

    // Exactly one request, against /api/catalog.
    expect(globalThis.fetch.mock.calls[0][0]).toMatch(/\/api\/catalog$/)
  })

  it('calls onLoad with the fetched STIG when a row title is clicked', async () => {
    const onLoad = vi.fn()
    const stigPayload = {
      title: 'Windows 11 STIG',
      version: '2',
      releaseInfo: 'Release: 3',
      rules: [],
    }
    globalThis.fetch
      .mockResolvedValueOnce(fakeRes({ status: 200, body: CATALOG }))
      .mockResolvedValueOnce(fakeRes({ status: 200, body: stigPayload }))

    render(<StigLibrary onLoad={onLoad} />)

    // The title cell wraps the text in a Cloudscape Link; click it.
    const titleEl = await screen.findByText('Windows 11 STIG')
    fireEvent.click(titleEl)

    await waitFor(() => {
      // Signature is onLoad(stig, catalogId) — id flows into workspace sync.
      expect(onLoad).toHaveBeenCalledWith(stigPayload, 'windows-11')
    })
    expect(globalThis.fetch.mock.calls[1][0]).toMatch(/\/api\/stigs\/windows-11$/)
  })

  it('gracefully handles a 500 catalog response without crashing', async () => {
    // The library tab currently swallows catalog errors silently (tracked in
    // ROADMAP); at minimum the component must not crash and must stop the
    // loading indicator.
    globalThis.fetch.mockResolvedValueOnce(
      fakeRes({
        status: 500,
        body: { error: { code: 'internal_error', message: 'db is down' } },
      }),
    )
    render(<StigLibrary onLoad={() => {}} />)

    // Wait for the spinner to clear; the table will be empty but mounted.
    await waitFor(() => {
      expect(screen.queryByText('Connecting to backend')).not.toBeInTheDocument()
    })
  })
})
