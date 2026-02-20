import { useRef, useEffect } from 'react'
import SeverityBadge from './badges/SeverityBadge.jsx'
import CCIMappingPanel from './CCIMappingPanel.jsx'
import { STATUS_OPTIONS, FINDING_DETAILS_FIELDS } from '../constants/status.js'
import s from './RuleDetail.module.css'

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
    <div className={s.panel} ref={panelRef}>
      {/* Sticky header */}
      <div className={s.header}>
        <div className={s.headerRow}>
          <div className={s.headerLeft}>
            <span className={s.stigId}>{rule.stigId}</span>
            <SeverityBadge severity={rule.severity} />
          </div>
          <button
            type="button"
            onClick={onClose}
            className={s.closeBtn}
            aria-label="Close detail panel"
          >
            ×
          </button>
        </div>
        <h2 className={s.ruleTitle}>{rule.title}</h2>
        <div className={s.metaRow}>
          <span className={s.metaText}>Rule ID: {rule.id}</span>
          {rule.cciIds.length > 0 && (
            <span className={s.metaText}>CCI: {rule.cciIds.join(', ')}</span>
          )}
        </div>
        {rule.cciIds.length > 0 && <CCIMappingPanel cciIds={rule.cciIds} />}
      </div>

      {/* Status selector */}
      <div className={s.statusSection}>
        <p className={s.sectionLabel}>Compliance Status</p>
        <div className={s.statusButtons}>
          {STATUS_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => onUpdateRule({ status: opt.value })}
              className={`${s.statusBtn} ${rule.status === opt.value ? s.statusBtnActive : ''}`}
              style={{ '--status-color': opt.color }}
              aria-pressed={rule.status === opt.value}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content sections */}
      <div className={s.body}>
        {CONTENT_SECTIONS.map(({ key, label, mono }) =>
          rule[key] ? (
            <div key={key} className={s.section}>
              <p className={s.sectionLabel}>{label}</p>
              <pre className={`${s.content} ${mono ? s.mono : ''}`}>{rule[key]}</pre>
            </div>
          ) : null,
        )}

        {/* Finding details & comments */}
        {FINDING_DETAILS_FIELDS.map(({ key, label }) => (
          <div key={key} className={s.section}>
            <label htmlFor={`field-${key}`} className={s.sectionLabel}>
              {label}
            </label>
            <textarea
              id={`field-${key}`}
              value={rule[key]}
              onChange={(e) => onUpdateRule({ [key]: e.target.value })}
              placeholder={`Enter ${label.toLowerCase()}…`}
              rows={4}
              className={s.textarea}
            />
          </div>
        ))}
      </div>
    </div>
  )
}
