import { useRef, useCallback } from 'react'
import TextFilter from '@cloudscape-design/components/text-filter'
import Button from '@cloudscape-design/components/button'
import SpaceBetween from '@cloudscape-design/components/space-between'
import Box from '@cloudscape-design/components/box'
import SeverityBadge from './badges/SeverityBadge.jsx'
import StatusBadge from './badges/StatusBadge.jsx'

export default function RuleList({
  rules,
  allRulesCount,
  selectedRuleId,
  searchTerm,
  onSearchChange,
  onSelectRule,
  onSetAllStatus,
}) {
  const listRef = useRef(null)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Search bar */}
      <div style={{ padding: '10px 12px', borderBottom: '1px solid #232f3e', flexShrink: 0 }}>
        <TextFilter
          filteringText={searchTerm}
          onChange={({ detail }) => onSearchChange(detail.filteringText)}
          filteringPlaceholder="Search by ID, title, or content…"
          countText={`${rules.length} of ${allRulesCount} rules`}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 6 }}>
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="inline-link" onClick={() => onSetAllStatus('not_a_finding')}>
              All NaF
            </Button>
            <Button variant="inline-link" onClick={() => onSetAllStatus('not_reviewed')}>
              Reset All
            </Button>
          </SpaceBetween>
        </div>
      </div>

      {/* Rule list */}
      <div ref={listRef} role="listbox" aria-label="Rules" style={{ flex: 1, overflowY: 'auto' }}>
        {rules.length === 0 ? (
          <Box textAlign="center" padding={{ vertical: 'l' }} color="text-status-inactive">
            No rules match the current filters
          </Box>
        ) : (
          rules.map((rule) => {
            const isSelected = selectedRuleId === rule.id
            return (
              <button
                key={rule.id}
                type="button"
                role="option"
                aria-selected={isSelected}
                onClick={() => onSelectRule(rule)}
                style={{
                  display: 'block',
                  width: '100%',
                  padding: '10px 14px',
                  border: 'none',
                  borderBottom: '1px solid #1a2332',
                  borderLeft: `3px solid ${isSelected ? '#539fe5' : 'transparent'}`,
                  background: isSelected ? '#539fe510' : 'transparent',
                  textAlign: 'left',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 12,
                    fontWeight: 700,
                    color: '#539fe5',
                    minWidth: 65,
                    flexShrink: 0,
                  }}>
                    {rule.stigId}
                  </span>
                  <SeverityBadge severity={rule.severity} />
                  <StatusBadge status={rule.status} />
                </div>
                <p style={{
                  fontSize: 13,
                  color: '#d1d5db',
                  lineHeight: 1.4,
                  display: '-webkit-box',
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: 'vertical',
                  overflow: 'hidden',
                  textAlign: 'left',
                  margin: 0,
                }}>
                  {rule.title}
                </p>
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}
