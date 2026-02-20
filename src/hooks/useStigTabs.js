import { useState, useCallback } from 'react'
import { parseXCCDF } from '../utils/parseXCCDF.js'
import { parseCKL } from '../utils/parseCKL.js'
import { generateSampleSTIG } from '../data/sampleStig.js'

function generateId() {
  return `tab-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
}

function makeTab(stig) {
  return { id: generateId(), stig, assetInfo: { hostname: '', ip: '', mac: '', fqdn: '' }, selectedRuleId: null }
}

export function useStigTabs() {
  const [tabs, setTabs] = useState([])
  const [activeTabId, setActiveTabId] = useState(null)
  const [diffPair, setDiffPairState] = useState(null) // [idA, idB] | null

  /** Parse and add one or more files as new tabs. */
  const addTabs = useCallback(async (files) => {
    const fileArray = Array.from(files)
    const newTabs = []
    for (const file of fileArray) {
      try {
        const text = await file.text()
        const stig = file.name.endsWith('.ckl') ? parseCKL(text) : parseXCCDF(text)
        newTabs.push(makeTab(stig))
      } catch (err) {
        // Surface parsing errors without crashing; the UI can show a toast later
        console.error(`Failed to parse ${file.name}:`, err)
      }
    }
    if (newTabs.length > 0) {
      setTabs((prev) => [...prev, ...newTabs])
      setActiveTabId(newTabs[0].id)
    }
  }, [])

  /** Add the built-in demo STIG as a new tab. */
  const addSampleTab = useCallback(() => {
    const tab = makeTab(generateSampleSTIG())
    setTabs((prev) => [...prev, tab])
    setActiveTabId(tab.id)
  }, [])

  /** Close a tab and move focus to the nearest remaining tab. */
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
    },
    [tabs],
  )

  const setActiveTab = useCallback((id) => setActiveTabId(id), [])

  const updateRule = useCallback((tabId, ruleId, updates) => {
    setTabs((prev) =>
      prev.map((t) =>
        t.id !== tabId
          ? t
          : { ...t, stig: { ...t.stig, rules: t.stig.rules.map((r) => (r.id === ruleId ? { ...r, ...updates } : r)) } },
      ),
    )
  }, [])

  const setAssetInfo = useCallback((tabId, info) => {
    setTabs((prev) => prev.map((t) => (t.id === tabId ? { ...t, assetInfo: info } : t)))
  }, [])

  const setSelectedRule = useCallback((tabId, ruleId) => {
    setTabs((prev) => prev.map((t) => (t.id === tabId ? { ...t, selectedRuleId: ruleId } : t)))
  }, [])

  const setAllStatus = useCallback((tabId, status) => {
    setTabs((prev) =>
      prev.map((t) =>
        t.id !== tabId
          ? t
          : { ...t, stig: { ...t.stig, rules: t.stig.rules.map((r) => ({ ...r, status })) } },
      ),
    )
  }, [])

  const setDiffPair = useCallback((pair) => setDiffPairState(pair), [])

  /** Load a pre-parsed STIG JSON received from the backend library API. */
  const addStigFromBackend = useCallback((stigJson) => {
    const tab = makeTab(stigJson)
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
  }
}
