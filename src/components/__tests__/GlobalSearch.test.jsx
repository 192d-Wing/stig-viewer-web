import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import GlobalSearch from '../GlobalSearch.jsx'

const rule = (overrides = {}) => ({
  id: 'R-1',
  stigId: 'V-1',
  title: 't',
  severity: 'CAT II',
  description: '',
  checkText: '',
  fixText: '',
  ...overrides,
})

const buildTabs = () => [
  {
    id: 'tab-a',
    stig: {
      title: 'Windows 11',
      rules: [
        rule({
          stigId: 'V-220001',
          id: 'SV-220001r1',
          title: 'Firewall must be enabled',
        }),
        rule({
          stigId: 'V-220002',
          id: 'SV-220002r1',
          title: 'Audit logging must be on',
        }),
      ],
    },
  },
  {
    id: 'tab-b',
    stig: {
      title: 'RHEL 9',
      rules: [
        rule({
          stigId: 'V-230001',
          id: 'SV-230001r1',
          title: 'SELinux must be enforcing',
        }),
      ],
    },
  },
]

describe('<GlobalSearch />', () => {
  const onNavigate = vi.fn()
  const onClose = vi.fn()

  beforeEach(() => {
    onNavigate.mockReset()
    onClose.mockReset()
  })

  it('shows the empty prompt when the query is blank', () => {
    render(
      <GlobalSearch
        isOpen
        onClose={onClose}
        tabs={buildTabs()}
        onNavigate={onNavigate}
      />,
    )
    expect(screen.getByText(/start typing to search/i)).toBeInTheDocument()
  })

  it('finds rules across every open tab by title', () => {
    render(
      <GlobalSearch
        isOpen
        onClose={onClose}
        tabs={buildTabs()}
        onNavigate={onNavigate}
      />,
    )
    const input = screen.getByPlaceholderText(/search by rule id/i)
    fireEvent.change(input, { target: { value: 'must' } })

    const list = screen.getByRole('listbox', { name: /search results/i })
    const options = within(list).getAllByRole('option')
    expect(options).toHaveLength(3)
    expect(within(list).getByText('Firewall must be enabled')).toBeInTheDocument()
    expect(within(list).getByText('SELinux must be enforcing')).toBeInTheDocument()
    expect(within(list).getByText('Audit logging must be on')).toBeInTheDocument()
  })

  it('ranks stigId prefix matches ahead of title matches', () => {
    render(
      <GlobalSearch
        isOpen
        onClose={onClose}
        tabs={buildTabs()}
        onNavigate={onNavigate}
      />,
    )
    fireEvent.change(screen.getByPlaceholderText(/search by rule id/i), {
      target: { value: 'V-22' },
    })
    const list = screen.getByRole('listbox', { name: /search results/i })
    const options = within(list).getAllByRole('option')
    // Two matches in Windows 11 tab; SELinux shouldn't match at all.
    expect(options).toHaveLength(2)
    expect(within(options[0]).getByText('V-220001')).toBeInTheDocument()
  })

  it('navigates and closes when a result is clicked', () => {
    render(
      <GlobalSearch
        isOpen
        onClose={onClose}
        tabs={buildTabs()}
        onNavigate={onNavigate}
      />,
    )
    fireEvent.change(screen.getByPlaceholderText(/search by rule id/i), {
      target: { value: 'selinux' },
    })
    const option = screen.getAllByRole('option')[0]
    fireEvent.click(option)
    expect(onNavigate).toHaveBeenCalledWith('tab-b', 'SV-230001r1')
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
