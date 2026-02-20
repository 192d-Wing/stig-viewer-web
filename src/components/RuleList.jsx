import { useRef, useCallback } from 'react'
import SeverityBadge from './badges/SeverityBadge.jsx'
import StatusBadge from './badges/StatusBadge.jsx'
import s from './RuleList.module.css'

export default function RuleList({
  rules,
  allRulesCount,
  selectedRuleId,
  searchTerm,
  onSearchChange,
  onSelectRule,
  onSetAllStatus,
}) {
  const clearSearch = useCallback(() => onSearchChange(''), [onSearchChange])
  const listRef = useRef(null)

  return (
    <div className={s.panel}>
      {/* Search bar */}
      <div className={s.searchBar}>
        <div className={s.searchWrap}>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            className={s.searchIcon}
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
          <input
            type="search"
            placeholder="Search by ID, title, or content…"
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            className={s.searchInput}
            aria-label="Search rules"
          />
          {searchTerm && (
            <button
              type="button"
              onClick={clearSearch}
              className={s.searchClear}
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </div>
        <div className={s.searchMeta}>
          <span className={s.ruleCount}>
            {rules.length} of {allRulesCount} rules
          </span>
          <div className={s.bulkActions}>
            <button
              type="button"
              onClick={() => onSetAllStatus('not_a_finding')}
              className={`${s.bulkBtn} ${s.nafBtn}`}
            >
              All NaF
            </button>
            <button
              type="button"
              onClick={() => onSetAllStatus('not_reviewed')}
              className={`${s.bulkBtn} ${s.resetBtn}`}
            >
              Reset All
            </button>
          </div>
        </div>
      </div>

      {/* Rule list */}
      <div className={s.list} ref={listRef} role="listbox" aria-label="Rules">
        {rules.length === 0 ? (
          <p className={s.empty}>No rules match the current filters</p>
        ) : (
          rules.map((rule) => (
            <button
              key={rule.id}
              type="button"
              role="option"
              aria-selected={selectedRuleId === rule.id}
              onClick={() => onSelectRule(rule)}
              className={`${s.ruleRow} ${selectedRuleId === rule.id ? s.selected : ''}`}
            >
              <div className={s.ruleHeader}>
                <span className={s.stigId}>{rule.stigId}</span>
                <SeverityBadge severity={rule.severity} />
                <StatusBadge status={rule.status} small />
              </div>
              <p className={s.ruleTitle}>{rule.title}</p>
            </button>
          ))
        )}
      </div>
    </div>
  )
}
