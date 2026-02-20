import { useState, useMemo, useRef, useCallback } from 'react'
import { exportCKL } from '../utils/exportCKL.js'
import { SEVERITY_COLORS, SEVERITY_ORDER } from '../constants/severity.js'
import { STATUS_OPTIONS } from '../constants/status.js'
import Header from '@cloudscape-design/components/header'
import Button from '@cloudscape-design/components/button'
import SpaceBetween from '@cloudscape-design/components/space-between'
import Container from '@cloudscape-design/components/container'
import ColumnLayout from '@cloudscape-design/components/column-layout'
import Box from '@cloudscape-design/components/box'
import Tabs from '@cloudscape-design/components/tabs'
import Badge from '@cloudscape-design/components/badge'
import StatusIndicator from '@cloudscape-design/components/status-indicator'
import ProgressBar from '@cloudscape-design/components/progress-bar'
import Select from '@cloudscape-design/components/select'
import FormField from '@cloudscape-design/components/form-field'
import Input from '@cloudscape-design/components/input'
import ExpandableSection from '@cloudscape-design/components/expandable-section'
import Link from '@cloudscape-design/components/link'
import RuleList from './RuleList.jsx'
import POAMExportModal from './POAMExportModal.jsx'

const SEVERITY_BADGE_COLOR = {
  'CAT I': 'red',
  'CAT II': 'blue',
  'CAT III': 'grey',
}

const STATUS_INDICATOR_TYPE = {
  not_reviewed: 'pending',
  not_a_finding: 'success',
  open: 'error',
  not_applicable: 'stopped',
}

const SEVERITY_FILTER_OPTIONS = [
  { label: 'All severities', value: '' },
  ...SEVERITY_ORDER.map((s) => ({ label: s, value: s })),
]

const STATUS_FILTER_OPTIONS = [
  { label: 'All statuses', value: '' },
  ...STATUS_OPTIONS.map((o) => ({ label: o.label, value: o.value })),
]

const ASSET_FIELDS = [
  { key: 'hostname', label: 'Hostname' },
  { key: 'ip', label: 'IP Address' },
  { key: 'mac', label: 'MAC Address' },
  { key: 'fqdn', label: 'FQDN' },
]

export default function STIGView({
  tab,
  onUpdateRule,
  onSetAssetInfo,
  onSetSelectedRule,
  onSetAllStatus,
  onAddFiles,
}) {
  const { stig, assetInfo, selectedRuleId } = tab

  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState(null)
  const [statusFilter, setStatusFilter] = useState(null)
  const [showPOAMModal, setShowPOAMModal] = useState(false)
  const fileInputRef = useRef(null)

  const filteredRules = useMemo(() => {
    return stig.rules.filter((r) => {
      if (severityFilter && r.severity !== severityFilter) return false
      if (statusFilter && r.status !== statusFilter) return false
      if (searchTerm) {
        const term = searchTerm.toLowerCase()
        return (
          r.title.toLowerCase().includes(term) ||
          r.stigId.toLowerCase().includes(term) ||
          r.id.toLowerCase().includes(term) ||
          r.description.toLowerCase().includes(term) ||
          r.checkText.toLowerCase().includes(term) ||
          r.fixText.toLowerCase().includes(term)
        )
      }
      return true
    })
  }, [stig.rules, searchTerm, severityFilter, statusFilter])

  const stats = useMemo(() => {
    const total = stig.rules.length
    const bySeverity = { 'CAT I': 0, 'CAT II': 0, 'CAT III': 0 }
    const byStatus = { not_reviewed: 0, not_a_finding: 0, open: 0, not_applicable: 0 }
    stig.rules.forEach((r) => {
      bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1
      byStatus[r.status] = (byStatus[r.status] ?? 0) + 1
    })
    const evaluated = total - byStatus.not_reviewed
    return {
      total,
      bySeverity,
      byStatus,
      evaluated,
      pct: total ? Math.round((evaluated / total) * 100) : 0,
    }
  }, [stig.rules])

  const handleExportCKL = useCallback(() => {
    const xml = exportCKL(stig, assetInfo.hostname, assetInfo.ip, assetInfo.mac, assetInfo.fqdn)
    const blob = new Blob([xml], { type: 'application/xml' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${stig.title.replace(/[^a-zA-Z0-9]/g, '_')}.ckl`
    anchor.click()
    URL.revokeObjectURL(url)
  }, [stig, assetInfo])

  const description = [
    stig.version && `v${stig.version}`,
    stig.releaseInfo,
  ].filter(Boolean).join(' · ')

  return (
    <SpaceBetween size="m">
      {/* Page header */}
      <Header
        variant="h2"
        description={description}
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            <Button onClick={() => fileInputRef.current?.click()}>Open File</Button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xml,.ckl"
              multiple
              style={{ display: 'none' }}
              aria-hidden="true"
              tabIndex={-1}
              onChange={(e) => {
                if (e.target.files && e.target.files.length > 0) onAddFiles(e.target.files)
              }}
            />
            <Button onClick={() => setShowPOAMModal(true)}>Export POAM</Button>
            <Button variant="primary" onClick={handleExportCKL}>Export .ckl</Button>
          </SpaceBetween>
        }
      >
        {stig.title}
      </Header>

      {/* Summary container */}
      <Container>
        <ColumnLayout columns={4} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">Total Rules</Box>
            <Box variant="awsui-value-large">{stats.total}</Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Evaluated</Box>
            <ProgressBar
              value={stats.pct}
              resultText={`${stats.evaluated} of ${stats.total}`}
              status={stats.pct === 100 ? 'success' : 'in-progress'}
            />
          </div>
          <div>
            <Box variant="awsui-key-label">Severity</Box>
            <SpaceBetween direction="horizontal" size="xs">
              {SEVERITY_ORDER.map((sev) => (
                <Badge key={sev} color={SEVERITY_BADGE_COLOR[sev]}>
                  {sev}: {stats.bySeverity[sev]}
                </Badge>
              ))}
            </SpaceBetween>
          </div>
          <div>
            <Box variant="awsui-key-label">Status</Box>
            <SpaceBetween size="xxs">
              {STATUS_OPTIONS.map((opt) => (
                <StatusIndicator key={opt.value} type={STATUS_INDICATOR_TYPE[opt.value]}>
                  {opt.label}: {stats.byStatus[opt.value]}
                </StatusIndicator>
              ))}
            </SpaceBetween>
          </div>
        </ColumnLayout>
      </Container>

      {/* Tabs */}
      <Tabs
        ariaLabel="STIG details"
        tabs={[
          {
            label: 'Rules',
            id: 'rules',
            content: (
              <SpaceBetween size="m">
                <SpaceBetween direction="horizontal" size="m" alignItems="end">
                  <FormField label="Severity">
                    <Select
                      selectedOption={
                        SEVERITY_FILTER_OPTIONS.find((o) => o.value === (severityFilter || '')) ||
                        SEVERITY_FILTER_OPTIONS[0]
                      }
                      onChange={({ detail }) =>
                        setSeverityFilter(detail.selectedOption.value || null)
                      }
                      options={SEVERITY_FILTER_OPTIONS}
                    />
                  </FormField>
                  <FormField label="Status">
                    <Select
                      selectedOption={
                        STATUS_FILTER_OPTIONS.find((o) => o.value === (statusFilter || '')) ||
                        STATUS_FILTER_OPTIONS[0]
                      }
                      onChange={({ detail }) =>
                        setStatusFilter(detail.selectedOption.value || null)
                      }
                      options={STATUS_FILTER_OPTIONS}
                    />
                  </FormField>
                </SpaceBetween>
                <div style={{ height: 'calc(100vh - 420px)', minHeight: 300 }}>
                  <RuleList
                    rules={filteredRules}
                    allRulesCount={stig.rules.length}
                    selectedRuleId={selectedRuleId}
                    searchTerm={searchTerm}
                    onSearchChange={setSearchTerm}
                    onSelectRule={(rule) => onSetSelectedRule(rule?.id ?? null)}
                    onSetAllStatus={onSetAllStatus}
                  />
                </div>
              </SpaceBetween>
            ),
          },
          {
            label: 'Details',
            id: 'details',
            content: (
              <Container header={<Header variant="h2">STIG Information</Header>}>
                <ColumnLayout columns={2} variant="text-grid">
                  <div>
                    <Box variant="awsui-key-label">Title</Box>
                    <div>{stig.title}</div>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Version</Box>
                    <div>{stig.version || '—'}</div>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Release</Box>
                    <div>{stig.releaseInfo?.match(/Release:\s*(\d+)/i)?.[1] || '—'}</div>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Benchmark Date</Box>
                    <div>{stig.releaseInfo?.match(/Benchmark Date:\s*(.+)/i)?.[1] || '—'}</div>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">Total Rules</Box>
                    <div>{stig.rules.length}</div>
                  </div>
                  <div>
                    <Box variant="awsui-key-label">DISA STIG Support</Box>
                    <Link href="mailto:disa.stig_spt@mail.mil" external>
                      disa.stig_spt@mail.mil
                    </Link>
                  </div>
                </ColumnLayout>
                {stig.description && (
                  <Box margin={{ top: 'l' }}>
                    <ExpandableSection headerText="Description" defaultExpanded>
                      <Box variant="p" color="text-body-secondary">
                        {stig.description}
                      </Box>
                    </ExpandableSection>
                  </Box>
                )}
              </Container>
            ),
          },
          {
            label: 'Asset',
            id: 'asset',
            content: (
              <Container header={<Header variant="h2">Asset Information</Header>}>
                <ColumnLayout columns={2}>
                  {ASSET_FIELDS.map(({ key, label }) => (
                    <FormField key={key} label={label}>
                      <Input
                        value={assetInfo[key]}
                        onChange={({ detail }) =>
                          onSetAssetInfo({ ...assetInfo, [key]: detail.value })
                        }
                      />
                    </FormField>
                  ))}
                </ColumnLayout>
              </Container>
            ),
          },
        ]}
      />

      <POAMExportModal
        show={showPOAMModal}
        onClose={() => setShowPOAMModal(false)}
        stig={stig}
        assetInfo={assetInfo}
      />
    </SpaceBetween>
  )
}
