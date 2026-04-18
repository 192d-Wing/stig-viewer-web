import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { bulkExportPOAMCSV, bulkExportPOAMJSON } from '../exportPOAM.js'
import { downloadSignedCKL } from '../bulkExport.js'

const rule = (overrides = {}) => ({
  id: 'R-1',
  stigId: 'V-1',
  title: 'title',
  severity: 'CAT II',
  description: 'desc',
  checkText: 'check',
  fixText: 'fix',
  cciIds: [],
  status: 'open',
  findingDetails: '',
  comments: '',
  ...overrides,
})

const tab = (overrides = {}) => ({
  id: 't1',
  assetInfo: { hostname: 'host-1', ip: '', mac: '', fqdn: '' },
  stig: {
    title: 'STIG A',
    version: '1',
    releaseInfo: 'Release: 1',
    rules: [rule({ stigId: 'V-100', status: 'open' })],
    ...(overrides.stig ?? {}),
  },
  ...overrides,
})

describe('bulkExportPOAMCSV', () => {
  it('emits one header row followed by rows from every tab', () => {
    const tabs = [
      tab({ id: 't1' }),
      tab({
        id: 't2',
        assetInfo: { hostname: 'host-2', ip: '', mac: '', fqdn: '' },
        stig: {
          title: 'STIG B',
          version: '1',
          releaseInfo: 'Release: 1',
          rules: [rule({ stigId: 'V-200', status: 'open' })],
        },
      }),
    ]
    const csv = bulkExportPOAMCSV(tabs)
    const lines = csv.split('\n')
    expect(lines[0]).toContain('Control Vulnerability ID')
    // One header + one row per tab = 3 lines.
    expect(lines).toHaveLength(3)
    expect(lines[1]).toContain('V-100')
    expect(lines[1]).toContain('host-1')
    expect(lines[2]).toContain('V-200')
    expect(lines[2]).toContain('host-2')
  })

  it('drops tabs with no open findings but keeps the header row', () => {
    const tabs = [
      tab({ stig: { title: 'X', rules: [rule({ status: 'not_a_finding' })] } }),
    ]
    const csv = bulkExportPOAMCSV(tabs)
    expect(csv.split('\n')).toHaveLength(1)
    expect(csv).toMatch(/Control Vulnerability ID/)
  })
})

describe('bulkExportPOAMJSON', () => {
  it('flattens rows from every tab into a single array', () => {
    const tabs = [
      tab({ stig: { title: 'A', rules: [rule({ stigId: 'V-100' })] } }),
      tab({ stig: { title: 'B', rules: [rule({ stigId: 'V-200' })] } }),
    ]
    const rows = bulkExportPOAMJSON(tabs)
    expect(rows).toHaveLength(2)
    expect(rows[0]['Control Vulnerability ID']).toBe('V-100')
    expect(rows[1]['Control Vulnerability ID']).toBe('V-200')
  })
})

describe('downloadSignedCKL', () => {
  const originalCreateObjectURL = URL.createObjectURL
  const originalRevokeObjectURL = URL.revokeObjectURL
  const downloads = []

  beforeEach(() => {
    downloads.length = 0
    vi.stubGlobal('fetch', vi.fn())
    URL.createObjectURL = () => 'blob:stub'
    URL.revokeObjectURL = () => {}

    // Capture <a>.click() calls so tests can assert two files were offered
    // to the browser.
    const origCreate = document.createElement.bind(document)
    document.createElement = (tag) => {
      const el = origCreate(tag)
      if (tag === 'a') {
        el.click = () => downloads.push(el.download)
      }
      return el
    }
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    URL.createObjectURL = originalCreateObjectURL
    URL.revokeObjectURL = originalRevokeObjectURL
    // document.createElement is restored by the reset in beforeEach.
  })

  it('POSTs the CKL bytes to /api/sign and downloads two files', async () => {
    const tab = {
      catalogId: 'windows-11',
      assetInfo: { hostname: 'host', ip: '', mac: '', fqdn: '' },
      stig: {
        title: 'Windows 11 STIG',
        version: '1',
        releaseInfo: 'Release: 1',
        rules: [
          {
            id: 'R-1',
            stigId: 'V-1',
            title: 't',
            severity: 'CAT II',
            status: 'open',
            findingDetails: '',
            comments: '',
            description: 'd',
            checkText: 'c',
            fixText: 'f',
            cciIds: [],
          },
        ],
      },
    }
    globalThis.fetch.mockResolvedValueOnce({
      status: 200,
      ok: true,
      json: async () => ({
        document: {
          algorithm: 'ed25519',
          sha256: 'abc',
          signed_at: '2025-01-01T00:00:00Z',
          signed_by: 'u1',
          signed_org: 'default',
          resource: 'windows-11',
        },
        signature: 'sig',
        keyId: 'deadbeef',
      }),
    })

    const bundle = await downloadSignedCKL(tab)

    expect(globalThis.fetch).toHaveBeenCalledTimes(1)
    const [url, init] = globalThis.fetch.mock.calls[0]
    expect(url).toMatch(/\/api\/sign$/)
    expect(init.method).toBe('POST')
    const sent = JSON.parse(init.body)
    expect(sent.resource).toBe('windows-11')
    // content is base64; decoding it should yield XML.
    const decoded = atob(sent.content)
    expect(decoded).toContain('<CHECKLIST>')

    expect(bundle.keyId).toBe('deadbeef')
    // Browser was handed two downloads in order: the .ckl then the sidecar.
    expect(downloads).toEqual([
      'Windows_11_STIG.ckl',
      'Windows_11_STIG.ckl.sig.json',
    ])
  })
})
