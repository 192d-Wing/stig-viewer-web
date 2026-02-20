import { useState, useMemo, useRef, useCallback } from 'react'
import { exportCKL } from '../utils/exportCKL.js'
import { SEVERITY_COLORS, SEVERITY_ORDER } from '../constants/severity.js'
import { STATUS_OPTIONS } from '../constants/status.js'
import StatCard from './StatCard.jsx'
import RuleList from './RuleList.jsx'
import RuleDetail from './RuleDetail.jsx'
import AssetModal from './AssetModal.jsx'
import POAMExportModal from './POAMExportModal.jsx'
import s from './STIGView.module.css'

export default function STIGView({
  tab,
  onUpdateRule,
  onSetAssetInfo,
  onSetSelectedRule,
  onSetAllStatus,
  onAddFiles,
}) {
  const { stig, assetInfo, selectedRuleId } = tab
  const selectedRule = useMemo(
    () => stig.rules.find((r) => r.id === selectedRuleId) ?? null,
    [stig.rules, selectedRuleId],
  )

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

  return (
    <div className={s.view}>
      {/* Header */}
      <header className={s.header}>
        <div className={s.headerInfo}>
          <span className={s.stigTitle}>{stig.title}</span>
          {stig.version && (
            <span className={s.headerMeta}>v{stig.version}</span>
          )}
          {stig.releaseInfo && (
            <span className={s.headerMeta}>{stig.releaseInfo}</span>
          )}
        </div>
        <div className={s.headerActions}>
          <button
            type="button"
            onClick={() => setShowAssetModal(true)}
            className={s.actionBtn}
          >
            Asset Info
          </button>
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className={s.actionBtn}
          >
            Open File
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".xml,.ckl"
            multiple
            className={s.hiddenInput}
            aria-hidden="true"
            tabIndex={-1}
            onChange={(e) => {
              if (e.target.files && e.target.files.length > 0) onAddFiles(e.target.files)
            }}
          />
          <button
            type="button"
            onClick={() => setShowPOAMModal(true)}
            className={s.actionBtn}
          >
            Export POAM
          </button>
          <button type="button" onClick={handleExportCKL} className={s.primaryBtn}>
            Export .ckl
          </button>
        </div>
      </header>

      {/* Stats bar */}
      <div className={s.statsBar} role="toolbar" aria-label="Filter by severity or status">
        <StatCard
          label="Total"
          value={stats.total}
          colorVar="var(--text-primary)"
          onClick={clearFilters}
          active={!severityFilter && !statusFilter}
        />
        <div className={s.divider} aria-hidden="true" />
        {SEVERITY_ORDER.map((sev) => (
          <StatCard
            key={sev}
            label={sev}
            value={stats.bySeverity[sev] ?? 0}
            colorVar={SEVERITY_COLORS[sev]}
            onClick={() => {
              setSeverityFilter(severityFilter === sev ? null : sev)
              setStatusFilter(null)
            }}
            active={severityFilter === sev}
          />
        ))}
        <div className={s.divider} aria-hidden="true" />
        {STATUS_OPTIONS.map((opt) => (
          <StatCard
            key={opt.value}
            label={opt.label}
            value={stats.byStatus[opt.value] ?? 0}
            colorVar={opt.color}
            onClick={() => {
              setStatusFilter(statusFilter === opt.value ? null : opt.value)
              setSeverityFilter(null)
            }}
            active={statusFilter === opt.value}
          />
        ))}
        <div className={s.spacer} />
        <div className={s.progress} aria-label={`${stats.pct}% evaluated`}>
          <span className={s.progressLabel}>Evaluated</span>
          <div className={s.progressRow}>
            <div className={s.progressBar}>
              <div
                className={`${s.progressFill} ${stats.pct === 100 ? s.progressComplete : ''}`}
                style={{ width: `${stats.pct}%` }}
              />
            </div>
            <span className={`${s.progressPct} ${stats.pct === 100 ? s.progressComplete : ''}`}>
              {stats.pct}%
            </span>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className={s.body}>
        <div className={`${s.listPane} ${selectedRule ? s.listPaneSplit : ''}`}>
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
        {selectedRule && (
          <RuleDetail
            rule={selectedRule}
            onUpdateRule={(updates) => onUpdateRule(selectedRule.id, updates)}
            onClose={() => onSetSelectedRule(null)}
          />
        )}
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
