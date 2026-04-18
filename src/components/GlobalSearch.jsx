import { useEffect, useMemo, useRef, useState } from 'react'
import Modal from '@cloudscape-design/components/modal'
import Input from '@cloudscape-design/components/input'
import Box from '@cloudscape-design/components/box'
import SpaceBetween from '@cloudscape-design/components/space-between'
import SeverityBadge from './badges/SeverityBadge.jsx'

// Cap the number of results we render to keep typing snappy on large libraries.
// 50 is enough that the user can scroll a bit without flooding the DOM.
const MAX_RESULTS = 50

function scoreRule(rule, term) {
  // Lower is better. 0 = no match. Cheap scoring — we just want a stable
  // ordering: stigId prefix > title > id > description > check/fix.
  const lower = term.toLowerCase()
  if (rule.stigId && rule.stigId.toLowerCase().startsWith(lower)) return 1
  if (rule.title && rule.title.toLowerCase().includes(lower)) return 2
  if (rule.id && rule.id.toLowerCase().includes(lower)) return 3
  if (rule.description && rule.description.toLowerCase().includes(lower)) return 4
  if (rule.checkText && rule.checkText.toLowerCase().includes(lower)) return 5
  if (rule.fixText && rule.fixText.toLowerCase().includes(lower)) return 6
  return 0
}

function collectMatches(tabs, term) {
  if (!term.trim()) return []
  const matches = []
  for (const tab of tabs) {
    for (const rule of tab.stig.rules) {
      const score = scoreRule(rule, term)
      if (score === 0) continue
      matches.push({ tabId: tab.id, tabTitle: tab.stig.title, rule, score })
      if (matches.length > MAX_RESULTS * 3) break
    }
    if (matches.length > MAX_RESULTS * 3) break
  }
  matches.sort((a, b) => a.score - b.score)
  return matches.slice(0, MAX_RESULTS)
}

export default function GlobalSearch({ isOpen, onClose, tabs, onNavigate }) {
  const [term, setTerm] = useState('')
  const [cursor, setCursor] = useState(0)
  const inputRef = useRef(null)

  const results = useMemo(() => collectMatches(tabs, term), [tabs, term])

  // Reset state every time the modal reopens so Ctrl+K feels fresh.
  useEffect(() => {
    if (!isOpen) return
    setTerm('')
    setCursor(0)
    // Focus runs on a microtask so Cloudscape has time to render.
    queueMicrotask(() => inputRef.current?.focus())
  }, [isOpen])

  // Clamp the cursor when the result set shrinks (e.g. user narrows query).
  useEffect(() => {
    if (cursor >= results.length) setCursor(Math.max(0, results.length - 1))
  }, [results.length, cursor])

  const confirm = (idx) => {
    const hit = results[idx]
    if (!hit) return
    onNavigate(hit.tabId, hit.rule.id)
    onClose()
  }

  const onKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setCursor((c) => Math.min(c + 1, Math.max(0, results.length - 1)))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setCursor((c) => Math.max(0, c - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      confirm(cursor)
    }
  }

  return (
    <Modal
      visible={isOpen}
      onDismiss={onClose}
      header="Search rules across all open STIGs"
      size="large"
      closeAriaLabel="Close search"
    >
      <SpaceBetween size="m">
        <div onKeyDownCapture={onKeyDown}>
          <Input
            ref={inputRef}
            value={term}
            onChange={({ detail }) => {
              setTerm(detail.value)
              setCursor(0)
            }}
            placeholder="Search by rule id, title, or text… (Esc to close)"
            ariaLabel="Search rules"
            autoFocus
          />
        </div>

        {term.trim() === '' ? (
          <Box color="text-status-inactive" textAlign="center" padding={{ vertical: 'l' }}>
            Start typing to search titles, rule IDs, descriptions, and check/fix text.
          </Box>
        ) : results.length === 0 ? (
          <Box color="text-status-inactive" textAlign="center" padding={{ vertical: 'l' }}>
            No rules match <strong>{term}</strong>.
          </Box>
        ) : (
          <ul
            style={{ listStyle: 'none', padding: 0, margin: 0, maxHeight: 400, overflowY: 'auto' }}
            role="listbox"
            aria-label="Search results"
          >
            {results.map((hit, idx) => {
              const active = idx === cursor
              return (
                <li key={`${hit.tabId}-${hit.rule.id}`}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={active}
                    onMouseEnter={() => setCursor(idx)}
                    onClick={() => confirm(idx)}
                    style={{
                      display: 'flex',
                      gap: 10,
                      alignItems: 'center',
                      width: '100%',
                      textAlign: 'left',
                      padding: '8px 10px',
                      background: active ? '#1e3a5f' : 'transparent',
                      color: '#d1d5db',
                      border: 0,
                      borderLeft: active ? '3px solid #539fe5' : '3px solid transparent',
                      borderRadius: 4,
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: 12,
                        fontWeight: 700,
                        color: '#539fe5',
                        minWidth: 72,
                      }}
                    >
                      {hit.rule.stigId}
                    </span>
                    <SeverityBadge severity={hit.rule.severity} />
                    <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {hit.rule.title}
                    </span>
                    <span style={{ fontSize: 11, color: '#8d99a8' }}>{hit.tabTitle}</span>
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </SpaceBetween>
    </Modal>
  )
}
