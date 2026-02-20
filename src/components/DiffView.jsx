import { useMemo } from 'react'
import { diffSTIGs } from '../utils/diffStig.js'
import Header from '@cloudscape-design/components/header'
import Button from '@cloudscape-design/components/button'
import Select from '@cloudscape-design/components/select'
import FormField from '@cloudscape-design/components/form-field'
import ExpandableSection from '@cloudscape-design/components/expandable-section'
import SpaceBetween from '@cloudscape-design/components/space-between'
import Box from '@cloudscape-design/components/box'
import ColumnLayout from '@cloudscape-design/components/column-layout'
import SeverityBadge from './badges/SeverityBadge.jsx'

const FIELD_LABELS = {
  title: 'Title',
  severity: 'Severity',
  description: 'Description',
  checkText: 'Check Text',
  fixText: 'Fix Text',
}

function ChangedEntry({ entry }) {
  return (
    <ExpandableSection
      headerText={
        <SpaceBetween direction="horizontal" size="xs" alignItems="center">
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: '#539fe5' }}>
            {entry.stigId}
          </span>
          <span style={{ fontSize: 11, color: '#f59e0b' }}>{entry.fields.join(', ')}</span>
        </SpaceBetween>
      }
    >
      <SpaceBetween size="m">
        {entry.fields.map((field) => (
          <div key={field}>
            <Box fontSize="body-s" fontWeight="bold" color="text-label" margin={{ bottom: 'xxs' }}>
              {FIELD_LABELS[field] ?? field}
            </Box>
            <ColumnLayout columns={2}>
              <div style={{
                padding: '6px 10px',
                borderRadius: 4,
                borderLeft: '3px solid #ff4444',
                background: '#ff444414',
              }}>
                <Box fontSize="body-s" color="text-status-inactive">A</Box>
                <pre style={{ fontSize: 12, color: '#d1d5db', whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0, lineHeight: 1.5 }}>
                  {entry.a[field]}
                </pre>
              </div>
              <div style={{
                padding: '6px 10px',
                borderRadius: 4,
                borderLeft: '3px solid #22c55e',
                background: '#22c55e14',
              }}>
                <Box fontSize="body-s" color="text-status-inactive">B</Box>
                <pre style={{ fontSize: 12, color: '#d1d5db', whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0, lineHeight: 1.5 }}>
                  {entry.b[field]}
                </pre>
              </div>
            </ColumnLayout>
          </div>
        ))}
      </SpaceBetween>
    </ExpandableSection>
  )
}

export default function DiffView({ tabs, diffPair, onSetDiffPair, onExitDiff }) {
  const [tabAId, tabBId] = diffPair ?? [null, null]
  const tabA = tabs.find((t) => t.id === tabAId) ?? null
  const tabB = tabs.find((t) => t.id === tabBId) ?? null

  const result = useMemo(() => {
    if (!tabA || !tabB) return null
    return diffSTIGs(tabA.stig, tabB.stig)
  }, [tabA, tabB])

  const handleSetA = (id) => onSetDiffPair([id, tabBId])
  const handleSetB = (id) => onSetDiffPair([tabAId, id])

  const tabOptions = tabs.map((t) => ({ value: t.id, label: t.stig.title }))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden', minHeight: 0 }}>
      {/* Selector row */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #354150', flexShrink: 0 }}>
        <Header
          variant="h2"
          actions={<Button onClick={onExitDiff}>Exit Diff</Button>}
        >
          STIG Version Diff
        </Header>
        <div style={{ marginTop: 12, display: 'flex', gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <FormField label="Baseline (A)">
            <Select
              selectedOption={tabOptions.find((o) => o.value === tabAId) || null}
              onChange={({ detail }) => handleSetA(detail.selectedOption.value)}
              options={tabOptions}
              placeholder="Select baseline"
            />
          </FormField>
          <Box padding={{ bottom: 'xs' }} color="text-status-inactive" fontWeight="bold">vs</Box>
          <FormField label="Compare (B)">
            <Select
              selectedOption={tabOptions.find((o) => o.value === tabBId) || null}
              onChange={({ detail }) => handleSetB(detail.selectedOption.value)}
              options={tabOptions}
              placeholder="Select comparison"
            />
          </FormField>
        </div>
      </div>

      {/* Results */}
      {!tabA || !tabB ? (
        <Box textAlign="center" padding={{ vertical: 'xxl' }} color="text-status-inactive" fontSize="heading-s">
          Select a Baseline and Compare STIG above to begin.
        </Box>
      ) : !result ? null : (
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          <SpaceBetween size="xl">
            {/* Added */}
            <ExpandableSection
              variant="container"
              headerText={`Added in B (${result.added.length})`}
              defaultExpanded
            >
              {result.added.length === 0 ? (
                <Box color="text-status-inactive">No rules added</Box>
              ) : (
                <SpaceBetween size="xs">
                  {result.added.map((rule) => (
                    <div key={rule.stigId} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '8px 12px', borderRadius: 6,
                      borderLeft: '3px solid #22c55e',
                      background: '#22c55e14',
                    }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: '#539fe5', minWidth: 65 }}>
                        {rule.stigId}
                      </span>
                      <SeverityBadge severity={rule.severity} />
                      <span style={{ fontSize: 13, color: '#d1d5db', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {rule.title}
                      </span>
                    </div>
                  ))}
                </SpaceBetween>
              )}
            </ExpandableSection>

            {/* Removed */}
            <ExpandableSection
              variant="container"
              headerText={`Removed from A (${result.removed.length})`}
              defaultExpanded
            >
              {result.removed.length === 0 ? (
                <Box color="text-status-inactive">No rules removed</Box>
              ) : (
                <SpaceBetween size="xs">
                  {result.removed.map((rule) => (
                    <div key={rule.stigId} style={{
                      display: 'flex', alignItems: 'center', gap: 8,
                      padding: '8px 12px', borderRadius: 6,
                      borderLeft: '3px solid #ff4444',
                      background: '#ff444414',
                    }}>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: '#539fe5', minWidth: 65 }}>
                        {rule.stigId}
                      </span>
                      <SeverityBadge severity={rule.severity} />
                      <span style={{ fontSize: 13, color: '#d1d5db', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {rule.title}
                      </span>
                    </div>
                  ))}
                </SpaceBetween>
              )}
            </ExpandableSection>

            {/* Changed */}
            <ExpandableSection
              variant="container"
              headerText={`Changed (${result.changed.length})`}
              defaultExpanded
            >
              {result.changed.length === 0 ? (
                <Box color="text-status-inactive">No rules changed</Box>
              ) : (
                <SpaceBetween size="s">
                  {result.changed.map((entry) => (
                    <ChangedEntry key={entry.stigId} entry={entry} />
                  ))}
                </SpaceBetween>
              )}
            </ExpandableSection>
          </SpaceBetween>
        </div>
      )}
    </div>
  )
}
