import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import STIGView from '../STIGView.jsx'

const rule = (overrides = {}) => ({
  id: 'R-1',
  stigId: 'V-1',
  title: 'title',
  severity: 'CAT II',
  description: 'd',
  checkText: 'c',
  fixText: 'f',
  cciIds: [],
  status: 'not_reviewed',
  findingDetails: '',
  comments: '',
  ...overrides,
})

const tab = (overrides = {}) => ({
  id: 'tab-1',
  selectedRuleId: null,
  assetInfo: { hostname: '', ip: '', mac: '', fqdn: '' },
  stig: {
    title: 'Sample STIG',
    version: '1',
    releaseInfo: 'Release: 2',
    rules: [
      rule({ stigId: 'V-1', severity: 'CAT I', status: 'open' }),
      rule({ stigId: 'V-2', id: 'R-2', severity: 'CAT II', status: 'not_a_finding' }),
      rule({ stigId: 'V-3', id: 'R-3', severity: 'CAT III', status: 'not_reviewed' }),
    ],
    ...(overrides.stig ?? {}),
  },
  ...overrides,
})

describe('<STIGView />', () => {
  const noop = vi.fn()

  it('renders the STIG title, version, and release in the header', () => {
    render(
      <STIGView
        tab={tab()}
        onUpdateRule={noop}
        onSetAssetInfo={noop}
        onSetSelectedRule={noop}
        onSetAllStatus={noop}
        onAddFiles={noop}
      />,
    )
    expect(screen.getByText('Sample STIG')).toBeInTheDocument()
    expect(screen.getByText(/v1 · Release: 2/)).toBeInTheDocument()
  })

  it('reports the total rule count in the summary grid', () => {
    render(
      <STIGView
        tab={tab()}
        onUpdateRule={noop}
        onSetAssetInfo={noop}
        onSetSelectedRule={noop}
        onSetAllStatus={noop}
        onAddFiles={noop}
      />,
    )
    expect(screen.getByText('Total Rules')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('exposes the POAM and .ckl export actions', () => {
    render(
      <STIGView
        tab={tab()}
        onUpdateRule={noop}
        onSetAssetInfo={noop}
        onSetSelectedRule={noop}
        onSetAllStatus={noop}
        onAddFiles={noop}
      />,
    )
    expect(
      screen.getByRole('button', { name: /export poam/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /export \.ckl/i }),
    ).toBeInTheDocument()
  })
})
