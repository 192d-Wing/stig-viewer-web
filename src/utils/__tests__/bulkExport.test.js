import { describe, it, expect } from 'vitest'
import { bulkExportPOAMCSV, bulkExportPOAMJSON } from '../exportPOAM.js'

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
