import { useState, useMemo } from 'react'
import { diffSTIGs } from '../utils/diffStig.js'
import SeverityBadge from './badges/SeverityBadge.jsx'
import s from './DiffView.module.css'

const FIELD_LABELS = {
  title: 'Title',
  severity: 'Severity',
  description: 'Description',
  checkText: 'Check Text',
  fixText: 'Fix Text',
}

function ChangedEntry({ entry }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className={s.changedEntry}>
      <button
        type="button"
        className={s.changedHeader}
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
      >
        <span className={s.changedId}>{entry.stigId}</span>
        <span className={s.changedFields}>{entry.fields.join(', ')}</span>
        <span className={s.expandIcon} aria-hidden="true">{expanded ? '▲' : '▼'}</span>
      </button>
      {expanded && (
        <div className={s.changedBody}>
          {entry.fields.map((field) => (
            <div key={field} className={s.fieldDiff}>
              <p className={s.fieldLabel}>{FIELD_LABELS[field] ?? field}</p>
              <div className={s.diffRows}>
                <div className={`${s.diffRow} ${s.diffRowA}`}>
                  <span className={s.diffSide}>A</span>
                  <pre className={s.diffText}>{entry.a[field]}</pre>
                </div>
                <div className={`${s.diffRow} ${s.diffRowB}`}>
                  <span className={s.diffSide}>B</span>
                  <pre className={s.diffText}>{entry.b[field]}</pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function TabPicker({ tabs, label, selected, onSelect }) {
  return (
    <div className={s.pickerGroup}>
      <p className={s.pickerLabel}>{label}</p>
      <div className={s.pickerOptions}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => onSelect(tab.id)}
            className={`${s.pickerBtn} ${selected === tab.id ? s.pickerBtnActive : ''}`}
            title={tab.stig.title}
          >
            {tab.stig.title}
          </button>
        ))}
      </div>
    </div>
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

  return (
    <div className={s.view}>
      {/* Selector row */}
      <div className={s.selector}>
        <h2 className={s.selectorTitle}>STIG Version Diff</h2>
        <div className={s.pickers}>
          <TabPicker tabs={tabs} label="Baseline (A)" selected={tabAId} onSelect={handleSetA} />
          <span className={s.vs} aria-hidden="true">vs</span>
          <TabPicker tabs={tabs} label="Compare (B)" selected={tabBId} onSelect={handleSetB} />
        </div>
        <button type="button" onClick={onExitDiff} className={s.exitBtn}>
          Exit Diff
        </button>
      </div>

      {/* Results */}
      {!tabA || !tabB ? (
        <p className={s.placeholder}>Select a Baseline and Compare STIG above to begin.</p>
      ) : !result ? null : (
        <div className={s.results}>
          {/* Added */}
          <section className={s.section}>
            <h3 className={`${s.sectionTitle} ${s.added}`}>
              Added in B ({result.added.length})
            </h3>
            {result.added.length === 0 ? (
              <p className={s.empty}>No rules added</p>
            ) : (
              result.added.map((rule) => (
                <div key={rule.stigId} className={`${s.ruleChip} ${s.ruleChipAdded}`}>
                  <span className={s.chipId}>{rule.stigId}</span>
                  <SeverityBadge severity={rule.severity} />
                  <span className={s.chipTitle}>{rule.title}</span>
                </div>
              ))
            )}
          </section>

          {/* Removed */}
          <section className={s.section}>
            <h3 className={`${s.sectionTitle} ${s.removed}`}>
              Removed from A ({result.removed.length})
            </h3>
            {result.removed.length === 0 ? (
              <p className={s.empty}>No rules removed</p>
            ) : (
              result.removed.map((rule) => (
                <div key={rule.stigId} className={`${s.ruleChip} ${s.ruleChipRemoved}`}>
                  <span className={s.chipId}>{rule.stigId}</span>
                  <SeverityBadge severity={rule.severity} />
                  <span className={s.chipTitle}>{rule.title}</span>
                </div>
              ))
            )}
          </section>

          {/* Changed */}
          <section className={s.section}>
            <h3 className={`${s.sectionTitle} ${s.changed}`}>
              Changed ({result.changed.length})
            </h3>
            {result.changed.length === 0 ? (
              <p className={s.empty}>No rules changed</p>
            ) : (
              result.changed.map((entry) => (
                <ChangedEntry key={entry.stigId} entry={entry} />
              ))
            )}
          </section>
        </div>
      )}
    </div>
  )
}
