import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import RuleDetail from '../RuleDetail.jsx'

const RULE = {
  id: 'SV-1000r1_rule',
  stigId: 'V-1000',
  title: 'Enforce audit logging',
  severity: 'CAT I',
  description: 'Audit logging MUST be enabled on all systems.',
  checkText: 'Run `auditctl -s`.',
  fixText: 'Enable auditd.',
  cciIds: ['CCI-000130', 'CCI-000131'],
  status: 'not_reviewed',
  findingDetails: '',
  comments: '',
}

describe('<RuleDetail />', () => {
  it('renders the rule identifier, title, and CCI mappings', () => {
    render(<RuleDetail rule={RULE} onUpdateRule={() => {}} onClose={() => {}} />)
    expect(screen.getByText('V-1000')).toBeInTheDocument()
    expect(screen.getByText('Enforce audit logging')).toBeInTheDocument()
    expect(screen.getByText(/Rule ID: SV-1000r1_rule/)).toBeInTheDocument()
    expect(screen.getByText(/CCI: CCI-000130, CCI-000131/)).toBeInTheDocument()
  })

  it('renders description, check, and fix sections when populated', () => {
    render(<RuleDetail rule={RULE} onUpdateRule={() => {}} onClose={() => {}} />)
    expect(
      screen.getByText('Audit logging MUST be enabled on all systems.'),
    ).toBeInTheDocument()
    expect(screen.getByText('Run `auditctl -s`.')).toBeInTheDocument()
    expect(screen.getByText('Enable auditd.')).toBeInTheDocument()
  })

  it('hides content sections that are empty', () => {
    const bare = { ...RULE, description: '', checkText: '', fixText: '' }
    render(<RuleDetail rule={bare} onUpdateRule={() => {}} onClose={() => {}} />)
    expect(screen.queryByText('Description')).not.toBeInTheDocument()
    expect(screen.queryByText('Check Text')).not.toBeInTheDocument()
    expect(screen.queryByText('Fix Text')).not.toBeInTheDocument()
  })

  it('calls onUpdateRule when a status segment is chosen', () => {
    const onUpdateRule = vi.fn()
    render(
      <RuleDetail rule={RULE} onUpdateRule={onUpdateRule} onClose={() => {}} />,
    )
    fireEvent.click(screen.getByText('Open'))
    expect(onUpdateRule).toHaveBeenCalledWith({ status: 'open' })
  })

  it('forwards finding-details edits', () => {
    const onUpdateRule = vi.fn()
    render(
      <RuleDetail rule={RULE} onUpdateRule={onUpdateRule} onClose={() => {}} />,
    )
    const textarea = screen.getByPlaceholderText(/enter finding details/i)
    fireEvent.change(textarea, { target: { value: 'Confirmed compliant' } })
    expect(onUpdateRule).toHaveBeenCalledWith({
      findingDetails: 'Confirmed compliant',
    })
  })

  it('calls onClose when the close button is pressed', () => {
    const onClose = vi.fn()
    render(<RuleDetail rule={RULE} onUpdateRule={() => {}} onClose={onClose} />)
    fireEvent.click(
      screen.getByRole('button', { name: /close detail panel/i }),
    )
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
