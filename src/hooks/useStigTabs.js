import { useState, useCallback, useRef, useEffect } from 'react'
import { parseXCCDF } from '../utils/parseXCCDF.js'
import { parseCKL } from '../utils/parseCKL.js'
import { generateSampleSTIG } from '../data/sampleStig.js'
import { apiFetch, UnauthorizedError } from '../api.js'
import { notify } from './useNotifications.js'

// Debounce window for workspace PUTs. Rapid toggles collapse into one save.
const SAVE_DEBOUNCE_MS = 1000

// Rule fields that matter for persistence. Everything else comes back from
// the catalog STIG on next load.
const RULE_OVERRIDE_FIELDS = ['status', 'findingDetails', 'comments']

// Max undo stack depth. Bulk "set all" counts as a single entry regardless of
// how many rules it touched.
const UNDO_LIMIT = 50

function generateId() {
  return `tab-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
}

function makeTab(stig, { catalogId = null, assetInfo } = {}) {
  return {
    id: generateId(),
    stig,
    assetInfo: assetInfo ?? { hostname: '', ip: '', mac: '', fqdn: '' },
    selectedRuleId: null,
    catalogId,
  }
}

// Serialize only the bits that belong in the workspace row. Used both for
// the PUT payload and to dedupe unchanged snapshots.
function buildWorkspacePayload(tab) {
  const ruleOverrides = {}
  for (const r of tab.stig.rules) {
    const hasOverride =
      r.status !== 'not_reviewed' ||
      (r.findingDetails && r.findingDetails.length > 0) ||
      (r.comments && r.comments.length > 0)
    if (!hasOverride) continue
    ruleOverrides[r.id] = {
      status: r.status,
      findingDetails: r.findingDetails || '',
      comments: r.comments || '',
    }
  }
  return { assetInfo: tab.assetInfo, ruleOverrides }
}

function snapshotKey(tab) {
  return JSON.stringify(buildWorkspacePayload(tab))
}

export function useStigTabs() {
  const [tabs, setTabs] = useState([])
  const [activeTabId, setActiveTabId] = useState(null)
  const [diffPair, setDiffPairState] = useState(null) // [idA, idB] | null

  // catalogId -> last-successful snapshot string. Used to skip re-PUTting
  // state we just loaded and to dedupe repeat saves.
  const savedSnapshots = useRef(new Map())
  // catalogId -> pending setTimeout id.
  const saveTimers = useRef(new Map())

  // Undo/redo history. Entries describe how to invert a prior mutation; a
  // ref is fine because consumers read via undo()/redo() on demand. We mirror
  // the can-undo / can-redo booleans into state so the toolbar updates.
  //
  // Entry shapes:
  //   { kind: 'rule',       tabId, ruleId, undo: {field: val, …}, redo: {…} }
  //   { kind: 'bulkStatus', tabId, priorStatuses: {ruleId: status, …},
  //                         status: string }
  //
  // `recording` is toggled off while undo/redo replay so replaying a history
  // entry doesn't itself get pushed onto the stack.
  const historyRef = useRef({ past: [], future: [], recording: true })
  const [historyState, setHistoryState] = useState({
    canUndo: false,
    canRedo: false,
  })
  const publishHistoryState = useCallback(() => {
    setHistoryState({
      canUndo: historyRef.current.past.length > 0,
      canRedo: historyRef.current.future.length > 0,
    })
  }, [])
  const pushHistory = useCallback(
    (entry) => {
      if (!historyRef.current.recording) return
      historyRef.current.past.push(entry)
      if (historyRef.current.past.length > UNDO_LIMIT) {
        historyRef.current.past.shift()
      }
      historyRef.current.future = []
      publishHistoryState()
    },
    [publishHistoryState],
  )

  // Ref of the current tabs so history capture can read prior state without
  // threading it through setTabs updaters (which would double-fire under
  // StrictMode).
  const tabsRef = useRef([])
  useEffect(() => {
    tabsRef.current = tabs
  }, [tabs])

  const saveNow = useCallback(async (tab) => {
    if (!tab.catalogId) return
    const payload = buildWorkspacePayload(tab)
    try {
      const res = await apiFetch(
        `/api/workspaces/${encodeURIComponent(tab.catalogId)}`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        },
      )
      if (!res.ok) throw new Error(`Server returned ${res.status}`)
      savedSnapshots.current.set(tab.catalogId, JSON.stringify(payload))
    } catch (err) {
      if (err instanceof UnauthorizedError) return
      notify.error(`Failed to save workspace: ${err.message}`)
    }
  }, [])

  const scheduleSave = useCallback(
    (tab) => {
      if (!tab.catalogId) return
      const existing = saveTimers.current.get(tab.catalogId)
      if (existing) clearTimeout(existing)
      const handle = setTimeout(() => {
        saveTimers.current.delete(tab.catalogId)
        saveNow(tab)
      }, SAVE_DEBOUNCE_MS)
      saveTimers.current.set(tab.catalogId, handle)
    },
    [saveNow],
  )

  // Watch tabs; schedule a save for any catalog-backed tab whose snapshot
  // diverges from what we last persisted.
  useEffect(() => {
    for (const tab of tabs) {
      if (!tab.catalogId) continue
      const current = snapshotKey(tab)
      if (savedSnapshots.current.get(tab.catalogId) === current) continue
      // Update the cached snapshot eagerly so subsequent renders don't
      // re-trigger until the user makes another change.
      savedSnapshots.current.set(tab.catalogId, current)
      scheduleSave(tab)
    }
  }, [tabs, scheduleSave])

  // Flush pending timers on unmount so we don't leak them across HMR.
  useEffect(() => {
    const timers = saveTimers.current
    return () => {
      for (const handle of timers.values()) clearTimeout(handle)
      timers.clear()
    }
  }, [])

  /** Parse and add one or more files as new tabs. File-based tabs are not persisted. */
  const addTabs = useCallback(async (files) => {
    const fileArray = Array.from(files)
    const newTabs = []
    for (const file of fileArray) {
      try {
        const text = await file.text()
        const stig = file.name.endsWith('.ckl') ? parseCKL(text) : parseXCCDF(text)
        newTabs.push(makeTab(stig))
      } catch (err) {
        console.error(`Failed to parse ${file.name}:`, err)
      }
    }
    if (newTabs.length > 0) {
      setTabs((prev) => [...prev, ...newTabs])
      setActiveTabId(newTabs[0].id)
    }
  }, [])

  const addSampleTab = useCallback(() => {
    const tab = makeTab(generateSampleSTIG())
    setTabs((prev) => [...prev, tab])
    setActiveTabId(tab.id)
  }, [])

  const removeTab = useCallback(
    (id) => {
      const remaining = tabs.filter((t) => t.id !== id)
      setTabs(remaining)
      setActiveTabId((prev) => {
        if (prev !== id) return prev
        if (remaining.length === 0) return null
        const closedIdx = tabs.findIndex((t) => t.id === id)
        return remaining[Math.min(closedIdx, remaining.length - 1)].id
      })
      setDiffPairState((prev) => {
        if (!prev || !prev.includes(id)) return prev
        return null
      })
      // Drop any history entries that targeted the closed tab; they'd no-op
      // or target the wrong row if we reused their ids later.
      historyRef.current.past = historyRef.current.past.filter(
        (e) => e.tabId !== id,
      )
      historyRef.current.future = historyRef.current.future.filter(
        (e) => e.tabId !== id,
      )
      publishHistoryState()
    },
    [tabs, publishHistoryState],
  )

  const setActiveTab = useCallback((id) => setActiveTabId(id), [])

  const applyRuleUpdate = useCallback((tabId, ruleId, updates) => {
    setTabs((prev) =>
      prev.map((t) =>
        t.id !== tabId
          ? t
          : {
              ...t,
              stig: {
                ...t.stig,
                rules: t.stig.rules.map((r) =>
                  r.id === ruleId ? { ...r, ...updates } : r,
                ),
              },
            },
      ),
    )
  }, [])

  const updateRule = useCallback(
    (tabId, ruleId, updates) => {
      const tab = tabsRef.current.find((t) => t.id === tabId)
      const rule = tab?.stig.rules.find((r) => r.id === ruleId)
      if (rule) {
        const prevFields = {}
        for (const k of Object.keys(updates)) {
          // Keys come from handler code, not user input, so bracket access is safe.
          // eslint-disable-next-line security/detect-object-injection
          prevFields[k] = rule[k]
        }
        pushHistory({
          kind: 'rule',
          tabId,
          ruleId,
          undo: prevFields,
          redo: { ...updates },
        })
      }
      applyRuleUpdate(tabId, ruleId, updates)
    },
    [applyRuleUpdate, pushHistory],
  )

  const setAssetInfo = useCallback((tabId, info) => {
    setTabs((prev) => prev.map((t) => (t.id === tabId ? { ...t, assetInfo: info } : t)))
  }, [])

  const setSelectedRule = useCallback((tabId, ruleId) => {
    setTabs((prev) => prev.map((t) => (t.id === tabId ? { ...t, selectedRuleId: ruleId } : t)))
  }, [])

  const applyBulkStatus = useCallback((tabId, perRule, fallbackStatus) => {
    setTabs((prev) =>
      prev.map((t) =>
        t.id !== tabId
          ? t
          : {
              ...t,
              stig: {
                ...t.stig,
                rules: t.stig.rules.map((r) => {
                  // If perRule has an entry for this rule, use it; otherwise
                  // apply the fallback (used by the forward "set all" path).
                  const next = perRule ? perRule[r.id] : fallbackStatus
                  return next === undefined ? r : { ...r, status: next }
                }),
              },
            },
      ),
    )
  }, [])

  const setAllStatus = useCallback(
    (tabId, status) => {
      const tab = tabsRef.current.find((t) => t.id === tabId)
      if (tab) {
        const priorStatuses = {}
        for (const r of tab.stig.rules) priorStatuses[r.id] = r.status
        pushHistory({
          kind: 'bulkStatus',
          tabId,
          priorStatuses,
          status,
        })
      }
      applyBulkStatus(tabId, null, status)
    },
    [applyBulkStatus, pushHistory],
  )

  const undo = useCallback(() => {
    const entry = historyRef.current.past.pop()
    if (!entry) return
    historyRef.current.recording = false
    try {
      if (entry.kind === 'rule') {
        applyRuleUpdate(entry.tabId, entry.ruleId, entry.undo)
      } else if (entry.kind === 'bulkStatus') {
        applyBulkStatus(entry.tabId, entry.priorStatuses, null)
      }
      historyRef.current.future.push(entry)
    } finally {
      historyRef.current.recording = true
      publishHistoryState()
    }
  }, [applyRuleUpdate, applyBulkStatus, publishHistoryState])

  const redo = useCallback(() => {
    const entry = historyRef.current.future.pop()
    if (!entry) return
    historyRef.current.recording = false
    try {
      if (entry.kind === 'rule') {
        applyRuleUpdate(entry.tabId, entry.ruleId, entry.redo)
      } else if (entry.kind === 'bulkStatus') {
        applyBulkStatus(entry.tabId, null, entry.status)
      }
      historyRef.current.past.push(entry)
    } finally {
      historyRef.current.recording = true
      publishHistoryState()
    }
  }, [applyRuleUpdate, applyBulkStatus, publishHistoryState])

  const setDiffPair = useCallback((pair) => setDiffPairState(pair), [])

  /** Load a pre-parsed STIG JSON received from the backend library API. */
  const addStigFromBackend = useCallback(async (stigJson, catalogId = null) => {
    let mergedStig = stigJson
    let assetInfo

    if (catalogId) {
      try {
        const res = await apiFetch(
          `/api/workspaces/${encodeURIComponent(catalogId)}`,
        )
        if (res.ok) {
          const ws = await res.json()
          if (ws.assetInfo && typeof ws.assetInfo === 'object') {
            assetInfo = {
              hostname: '',
              ip: '',
              mac: '',
              fqdn: '',
              ...ws.assetInfo,
            }
          }
          if (ws.ruleOverrides && typeof ws.ruleOverrides === 'object') {
            mergedStig = {
              ...stigJson,
              rules: stigJson.rules.map((r) => {
                const o = ws.ruleOverrides[r.id]
                if (!o) return r
                const patch = {}
                for (const k of RULE_OVERRIDE_FIELDS) {
                  // `k` is from a fixed const whitelist, so bracket access is safe.
                  // eslint-disable-next-line security/detect-object-injection
                  if (o[k] !== undefined) patch[k] = o[k]
                }
                return { ...r, ...patch }
              }),
            }
          }
        }
        // 404 is the normal "no saved state yet" case and is ignored.
      } catch (err) {
        if (!(err instanceof UnauthorizedError)) {
          console.warn('workspace fetch failed', err)
        }
      }
    }

    const tab = makeTab(mergedStig, { catalogId, assetInfo })
    // Seed the snapshot so the effect doesn't immediately re-PUT what we
    // just loaded.
    if (catalogId) {
      savedSnapshots.current.set(catalogId, snapshotKey(tab))
    }
    setTabs((prev) => [...prev, tab])
    setActiveTabId(tab.id)
  }, [])

  return {
    tabs,
    activeTabId,
    diffPair,
    addTabs,
    addSampleTab,
    addStigFromBackend,
    removeTab,
    setActiveTab,
    updateRule,
    setAssetInfo,
    setSelectedRule,
    setAllStatus,
    setDiffPair,
    undo,
    redo,
    canUndo: historyState.canUndo,
    canRedo: historyState.canRedo,
  }
}
