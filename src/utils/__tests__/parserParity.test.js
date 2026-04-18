import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { parseXCCDF } from '../parseXCCDF.js'

// Shared fixture — any drift here must be mirrored in the backend parity
// test in backend/src/parser/mod.rs. See testdata/fixtures/README is below
// implicit in the comment at the top of the XML file itself.
const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = resolve(
  __dirname,
  '../../../testdata/fixtures/minimal.xccdf.xml',
)
const XML = readFileSync(FIXTURE_PATH, 'utf8')

describe('parseXCCDF parity fixture', () => {
  it('extracts the STIG-level title and version', () => {
    const stig = parseXCCDF(XML)
    expect(stig.title).toBe('Parity Fixture STIG')
    expect(stig.version).toBe('2')
  })

  it('parses exactly three rules with the expected ids and severities', () => {
    const stig = parseXCCDF(XML)
    expect(stig.rules).toHaveLength(3)

    const byStigId = new Map(stig.rules.map((r) => [r.stigId, r]))

    expect(byStigId.get('V-1001').severity).toBe('CAT I')
    expect(byStigId.get('V-1001').id).toBe('SV-1001r1_rule')
    expect(byStigId.get('V-1001').title).toBe('Critical rule under test')

    expect(byStigId.get('V-1002').severity).toBe('CAT II')
    expect(byStigId.get('V-1002').id).toBe('SV-1002r1_rule')

    expect(byStigId.get('V-1003').severity).toBe('CAT III')
    expect(byStigId.get('V-1003').id).toBe('SV-1003r1_rule')
  })

  it('strips VulnDiscussion + FalsePositives from descriptions', () => {
    const stig = parseXCCDF(XML)
    const critical = stig.rules.find((r) => r.id === 'SV-1001r1_rule')
    expect(critical.description).toBe('Why this critical finding matters.')
    expect(critical.description).not.toContain('FalsePositives')
    expect(critical.description).not.toContain('<')
  })

  it('collects CCI references per rule', () => {
    const stig = parseXCCDF(XML)
    const critical = stig.rules.find((r) => r.id === 'SV-1001r1_rule')
    expect(critical.cciIds).toEqual(['CCI-000015', 'CCI-000017'])
    const low = stig.rules.find((r) => r.stigId === 'V-1003')
    expect(low.cciIds).toEqual([])
  })

  it('initialises every rule to not_reviewed with empty override fields', () => {
    const stig = parseXCCDF(XML)
    for (const r of stig.rules) {
      expect(r.status).toBe('not_reviewed')
      expect(r.findingDetails).toBe('')
      expect(r.comments).toBe('')
    }
  })
})
