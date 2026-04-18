import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import DiffView from '../DiffView.jsx'

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

const buildTabs = () => [
  {
    id: 'tab-a',
    stig: {
      title: 'STIG A',
      version: '1',
      releaseInfo: 'Release: 1',
      rules: [
        rule({ stigId: 'V-1', title: 'old' }),
        rule({ stigId: 'V-2', id: 'R-2', title: 'removed only in A' }),
      ],
    },
  },
  {
    id: 'tab-b',
    stig: {
      title: 'STIG B',
      version: '2',
      releaseInfo: 'Release: 2',
      rules: [
        rule({ stigId: 'V-1', title: 'new' }),
        rule({ stigId: 'V-3', id: 'R-3', title: 'added in B' }),
      ],
    },
  },
]

describe('<DiffView />', () => {
  it('shows a placeholder when either side is unselected', () => {
    render(
      <DiffView
        tabs={buildTabs()}
        diffPair={[null, null]}
        onSetDiffPair={() => {}}
        onExitDiff={() => {}}
      />,
    )
    expect(
      screen.getByText(/Select a Baseline and Compare STIG above/i),
    ).toBeInTheDocument()
  })

  it('renders added / removed / changed section counts when both sides are set', () => {
    render(
      <DiffView
        tabs={buildTabs()}
        diffPair={['tab-a', 'tab-b']}
        onSetDiffPair={() => {}}
        onExitDiff={() => {}}
      />,
    )
    // Diff between fixtures: V-3 added, V-2 removed, V-1 changed (title)
    expect(screen.getByText('Added in B (1)')).toBeInTheDocument()
    expect(screen.getByText('Removed from A (1)')).toBeInTheDocument()
    expect(screen.getByText('Changed (1)')).toBeInTheDocument()

    // Titles from each section are visible
    expect(screen.getByText('added in B')).toBeInTheDocument()
    expect(screen.getByText('removed only in A')).toBeInTheDocument()
  })

  it('calls onExitDiff when the Exit Diff button is pressed', () => {
    const onExitDiff = vi.fn()
    render(
      <DiffView
        tabs={buildTabs()}
        diffPair={['tab-a', 'tab-b']}
        onSetDiffPair={() => {}}
        onExitDiff={onExitDiff}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /exit diff/i }))
    expect(onExitDiff).toHaveBeenCalledTimes(1)
  })
})
