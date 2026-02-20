import { useRef, useCallback } from 'react'
import s from './TabBar.module.css'

export default function TabBar({ tabs, activeTabId, diffPair, onActivate, onClose, onAddFiles, onDiff }) {
  const fileInputRef = useRef(null)

  const handleFiles = useCallback(
    (files) => {
      if (files && files.length > 0) onAddFiles(files)
    },
    [onAddFiles],
  )

  // Determine if diff mode is active or possible
  const isDiffActive = diffPair !== null
  const canDiff = tabs.length >= 2

  return (
    <div className={s.bar} role="tablist" aria-label="Open STIGs">
      {/* Logo */}
      <div className={s.logo} aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 40 40" fill="none">
          <rect width="40" height="40" rx="8" fill="#c9a227" />
          <path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1115" />
          <path d="M28 22l4 4-4 4" stroke="#0f1115" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className={s.logoText}>STIG Viewer</span>
      </div>

      <div className={s.divider} aria-hidden="true" />

      {/* Tab list */}
      <div className={s.tabs}>
        {tabs.map((tab) => {
          const isActive = tab.id === activeTabId && !isDiffActive
          const inDiff = diffPair?.includes(tab.id)
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => onActivate(tab.id)}
              className={`${s.tab} ${isActive ? s.active : ''} ${inDiff ? s.inDiff : ''}`}
              title={tab.stig.title}
            >
              <span className={s.tabText}>{tab.stig.title}</span>
              <span
                className={`${s.tabClose} ${isActive ? s.tabCloseVisible : ''}`}
                role="button"
                tabIndex={0}
                aria-label={`Close ${tab.stig.title}`}
                onClick={(e) => {
                  e.stopPropagation()
                  onClose(tab.id)
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    e.stopPropagation()
                    onClose(tab.id)
                  }
                }}
                aria-hidden="false"
              >
                ×
              </span>
            </button>
          )
        })}
      </div>

      {/* Add tab button */}
      <button
        type="button"
        onClick={() => fileInputRef.current?.click()}
        className={s.addBtn}
        aria-label="Open additional STIG files"
        title="Open files"
      >
        +
      </button>
      <input
        ref={fileInputRef}
        type="file"
        accept=".xml,.ckl"
        multiple
        className={s.hiddenInput}
        aria-hidden="true"
        tabIndex={-1}
        onChange={(e) => handleFiles(e.target.files)}
      />

      <div className={s.spacer} />

      {/* Diff button */}
      {canDiff && (
        <button
          type="button"
          onClick={() => onDiff(isDiffActive ? null : [])}
          className={`${s.diffBtn} ${isDiffActive ? s.diffActive : ''}`}
          aria-pressed={isDiffActive}
          title="Compare two STIG versions"
        >
          {isDiffActive ? 'Exit Diff' : 'Diff'}
        </button>
      )}
    </div>
  )
}
