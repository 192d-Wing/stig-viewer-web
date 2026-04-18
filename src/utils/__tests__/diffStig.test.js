import { describe, it, expect } from 'vitest'
import { diffSTIGs } from '../diffStig.js'

const rule = (overrides = {}) => ({
  id: 'R-1',
  stigId: 'V-1',
  title: 'title',
  severity: 'CAT II',
  description: 'desc',
  checkText: 'check',
  fixText: 'fix',
  status: 'not_reviewed',
  ...overrides,
})

const stig = (rules) => ({ title: 't', rules })

describe('diffSTIGs', () => {
  it('returns empty diff when both STIGs are identical', () => {
    const a = stig([rule({ stigId: 'V-1' }), rule({ stigId: 'V-2', id: 'R-2' })])
    const b = stig([rule({ stigId: 'V-1' }), rule({ stigId: 'V-2', id: 'R-2' })])
    expect(diffSTIGs(a, b)).toEqual({ added: [], removed: [], changed: [] })
  })

  it('detects added rules (present in B, absent in A)', () => {
    const a = stig([rule({ stigId: 'V-1' })])
    const b = stig([rule({ stigId: 'V-1' }), rule({ stigId: 'V-NEW', id: 'R-NEW' })])
    const d = diffSTIGs(a, b)
    expect(d.added).toHaveLength(1)
    expect(d.added[0].stigId).toBe('V-NEW')
    expect(d.removed).toEqual([])
    expect(d.changed).toEqual([])
  })

  it('detects removed rules (present in A, absent in B)', () => {
    const a = stig([rule({ stigId: 'V-1' }), rule({ stigId: 'V-OLD', id: 'R-OLD' })])
    const b = stig([rule({ stigId: 'V-1' })])
    const d = diffSTIGs(a, b)
    expect(d.removed).toHaveLength(1)
    expect(d.removed[0].stigId).toBe('V-OLD')
    expect(d.added).toEqual([])
    expect(d.changed).toEqual([])
  })

  it('detects changed fields while ignoring status', () => {
    const a = stig([rule({ stigId: 'V-1', title: 'old', status: 'open' })])
    const b = stig([rule({ stigId: 'V-1', title: 'new', status: 'not_a_finding' })])
    const d = diffSTIGs(a, b)
    expect(d.changed).toHaveLength(1)
    expect(d.changed[0].fields).toEqual(['title'])
    expect(d.changed[0].a).toEqual({ title: 'old' })
    expect(d.changed[0].b).toEqual({ title: 'new' })
  })

  it('collects all diffed fields in a single entry', () => {
    const a = stig([rule({ stigId: 'V-1', title: 'A', severity: 'CAT II', fixText: 'fa' })])
    const b = stig([rule({ stigId: 'V-1', title: 'B', severity: 'CAT I', fixText: 'fb' })])
    const d = diffSTIGs(a, b)
    expect(d.changed).toHaveLength(1)
    expect(d.changed[0].fields.sort()).toEqual(['fixText', 'severity', 'title'])
  })

  it('handles empty rule arrays on both sides', () => {
    expect(diffSTIGs(stig([]), stig([]))).toEqual({
      added: [],
      removed: [],
      changed: [],
    })
  })
})
