import { useState, useMemo, useRef, useCallback } from 'react'
import { exportCKL } from '../utils/exportCKL.js'
import { SEVERITY_COLORS, SEVERITY_ORDER } from '../constants/severity.js'
import { STATUS_OPTIONS } from '../constants/status.js'
import Header from '@cloudscape-design/components/header'
import Button from '@cloudscape-design/components/button'
import SpaceBetween from '@cloudscape-design/components/space-between'
import ProgressBar from '@cloudscape-design/components/progress-bar'
import StatCard from './StatCard.jsx'
import RuleList from './RuleList.jsx'
import AssetModal from './AssetModal.jsx'
import POAMExportModal from './POAMExportModal.jsx'

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
  const [showAssetModal, setShowAssetModal] = useState(false)
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

  const clearFilters = useCallback(() => {
    setSeverityFilter(null)
    setStatusFilter(null)
  }, [])

  const description = [
    stig.version && `v${stig.version}`,
    stig.releaseInfo,
  ].filter(Boolean).join(' \u00b7 ')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', minHeight: 0 }}>
      {/* Header */}
      <div style={{ padding: '8px 16px', borderBottom: '1px solid #354150', flexShrink: 0 }}>
        <Header
          variant="h2"
          description={description}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setShowAssetModal(true)}>Asset Info</Button>
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
      </div>

      {/* Stats bar */}
      <div
        role="toolbar"
        aria-label="Filter by severity or status"
        style={{
          padding: '10px 16px',
          display: 'flex',
          gap: 8,
          alignItems: 'center',
          borderBottom: '1px solid #232f3e',
          overflowX: 'auto',
          flexShrink: 0,
          scrollbarWidth: 'none',
        }}
      >
        <StatCard
          label="Total"
          value={stats.total}
          color="#d1d5db"
          onClick={clearFilters}
          active={!severityFilter && !statusFilter}
        />
        <div style={{ width: 1, height: 36, background: '#354150', flexShrink: 0 }} aria-hidden="true" />
        {SEVERITY_ORDER.map((sev) => (
          <StatCard
            key={sev}
            label={sev}
            value={stats.bySeverity[sev] ?? 0}
            color={SEVERITY_COLORS[sev]}
            onClick={() => {
              setSeverityFilter(severityFilter === sev ? null : sev)
              setStatusFilter(null)
            }}
            active={severityFilter === sev}
          />
        ))}
        <div style={{ width: 1, height: 36, background: '#354150', flexShrink: 0 }} aria-hidden="true" />
        {STATUS_OPTIONS.map((opt) => (
          <StatCard
            key={opt.value}
            label={opt.label}
            value={stats.byStatus[opt.value] ?? 0}
            color={opt.color}
            onClick={() => {
              setStatusFilter(statusFilter === opt.value ? null : opt.value)
              setSeverityFilter(null)
            }}
            active={statusFilter === opt.value}
          />
        ))}
        <div style={{ flex: 1 }} />
        <div style={{ minWidth: 120, flexShrink: 0 }}>
          <ProgressBar
            value={stats.pct}
            label="Evaluated"
            resultText={`${stats.pct}%`}
            status={stats.pct === 100 ? 'success' : 'in-progress'}
          />
        </div>
      </div>

      {/* Rule list — full width, RuleDetail is in AppLayout SplitPanel */}
      <div style={{ flex: 1, overflow: 'hidden', minHeight: 0 }}>
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

      <AssetModal
        show={showAssetModal}
        onClose={() => setShowAssetModal(false)}
        assetInfo={assetInfo}
        onUpdate={onSetAssetInfo}
      />
      <POAMExportModal
        show={showPOAMModal}
        onClose={() => setShowPOAMModal(false)}
        stig={stig}
        assetInfo={assetInfo}
      />
    </div>
  )
}
