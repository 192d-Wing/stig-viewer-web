import { useRef, useEffect } from 'react'
import Header from '@cloudscape-design/components/header'
import Button from '@cloudscape-design/components/button'
import SpaceBetween from '@cloudscape-design/components/space-between'
import SegmentedControl from '@cloudscape-design/components/segmented-control'
import ExpandableSection from '@cloudscape-design/components/expandable-section'
import FormField from '@cloudscape-design/components/form-field'
import Textarea from '@cloudscape-design/components/textarea'
import Box from '@cloudscape-design/components/box'
import SeverityBadge from './badges/SeverityBadge.jsx'
import CCIMappingPanel from './CCIMappingPanel.jsx'
import { STATUS_OPTIONS, FINDING_DETAILS_FIELDS } from '../constants/status.js'

const CONTENT_SECTIONS = [
  { key: 'description', label: 'Description', mono: false },
  { key: 'checkText', label: 'Check Text', mono: true },
  { key: 'fixText', label: 'Fix Text', mono: false },
]

export default function RuleDetail({ rule, onUpdateRule, onClose }) {
  const panelRef = useRef(null)

  useEffect(() => {
    if (panelRef.current) panelRef.current.scrollTop = 0
  }, [rule.id])

  return (
    <div ref={panelRef} style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', minWidth: 0 }}>
      {/* Header */}
      <div style={{
        padding: '16px 20px',
        borderBottom: '1px solid #232f3e',
        position: 'sticky',
        top: 0,
        zIndex: 10,
        background: '#0f1b2eee',
        backdropFilter: 'blur(12px)',
        flexShrink: 0,
      }}>
        <Header
          variant="h2"
          actions={
            <Button variant="icon" iconName="close" onClick={onClose} ariaLabel="Close detail panel" />
          }
          description={
            <SpaceBetween direction="horizontal" size="xs">
              <span>Rule ID: {rule.id}</span>
              {rule.cciIds.length > 0 && (
                <span>CCI: {rule.cciIds.join(', ')}</span>
              )}
            </SpaceBetween>
          }
        >
          <SpaceBetween direction="horizontal" size="xs" alignItems="center">
            <span>{rule.stigId}</span>
            <SeverityBadge severity={rule.severity} />
          </SpaceBetween>
        </Header>
        <Box margin={{ top: 'xs' }} fontSize="body-m" fontWeight="bold" color="text-body-secondary">
          {rule.title}
        </Box>
        {rule.cciIds.length > 0 && <CCIMappingPanel cciIds={rule.cciIds} />}
      </div>

      {/* Status selector */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #232f3e', flexShrink: 0 }}>
        <Box margin={{ bottom: 'xs' }} fontSize="body-s" fontWeight="bold" color="text-label">
          Compliance Status
        </Box>
        <SegmentedControl
          selectedId={rule.status}
          onChange={({ detail }) => onUpdateRule({ status: detail.selectedId })}
          options={STATUS_OPTIONS.map((opt) => ({
            id: opt.value,
            text: opt.label,
          }))}
        />
      </div>

      {/* Content sections */}
      <div style={{ padding: '0 20px 24px', flex: 1 }}>
        <SpaceBetween size="m">
          {CONTENT_SECTIONS.map(({ key, label, mono }) =>
            rule[key] ? (
              <ExpandableSection key={key} headerText={label} defaultExpanded>
                <pre style={{
                  fontSize: mono ? 12 : 13,
                  lineHeight: 1.65,
                  color: '#8d99a8',
                  background: '#0f1b2e80',
                  border: '1px solid #354150',
                  borderRadius: 6,
                  padding: '12px 14px',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontFamily: mono ? "'JetBrains Mono', monospace" : 'inherit',
                  margin: 0,
                }}>
                  {rule[key]}
                </pre>
              </ExpandableSection>
            ) : null,
          )}

          {/* Finding details & comments */}
          {FINDING_DETAILS_FIELDS.map(({ key, label }) => (
            <FormField key={key} label={label}>
              <Textarea
                value={rule[key]}
                onChange={({ detail }) => onUpdateRule({ [key]: detail.value })}
                placeholder={`Enter ${label.toLowerCase()}…`}
                rows={4}
              />
            </FormField>
          ))}
        </SpaceBetween>
      </div>
    </div>
  )
}
