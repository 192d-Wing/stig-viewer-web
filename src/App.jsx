import { useState, useMemo, useRef, useCallback } from 'react'
import { useStigTabs } from './hooks/useStigTabs.js'
import TopNavigation from '@cloudscape-design/components/top-navigation'
import AppLayout from '@cloudscape-design/components/app-layout'
import SideNavigation from '@cloudscape-design/components/side-navigation'
import SplitPanel from '@cloudscape-design/components/split-panel'
import Button from '@cloudscape-design/components/button'
import DropZone from './components/DropZone.jsx'
import StigLibrary from './components/StigLibrary.jsx'
import STIGView from './components/STIGView.jsx'
import DiffView from './components/DiffView.jsx'
import RuleDetail from './components/RuleDetail.jsx'

export default function App() {
  const {
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
  } = useStigTabs()

  const [navOpen, setNavOpen] = useState(true)
  const [splitPanelOpen, setSplitPanelOpen] = useState(true)
  const fileInputRef = useRef(null)

  const activeTab = tabs.find((t) => t.id === activeTabId) ?? null
  const isDiffMode = diffPair !== null
  const hasTabs = tabs.length > 0

  const selectedRule = useMemo(() => {
    if (!activeTab) return null
    return activeTab.stig.rules.find((r) => r.id === activeTab.selectedRuleId) ?? null
  }, [activeTab])

  const handleDiffToggle = useCallback(() => {
    if (isDiffMode) {
      setDiffPair(null)
    } else {
      setDiffPair([tabs[0]?.id ?? null, tabs[1]?.id ?? null])
    }
  }, [isDiffMode, tabs, setDiffPair])

  const handleFileInput = useCallback(
    (e) => {
      if (e.target.files && e.target.files.length > 0) addTabs(e.target.files)
    },
    [addTabs],
  )

  const handleSplitPanelToggle = useCallback(
    ({ detail }) => {
      if (!detail.open) {
        // User closed the split panel — deselect rule
        if (activeTab) setSelectedRule(activeTab.id, null)
      }
      setSplitPanelOpen(detail.open)
    },
    [activeTab, setSelectedRule],
  )

  // Open split panel automatically when a rule is selected
  const effectiveSplitOpen = selectedRule ? splitPanelOpen : false

  // Build TopNavigation utilities
  const utilities = []
  if (hasTabs) {
    utilities.push({
      type: 'button',
      text: 'Open File',
      iconName: 'upload',
      onClick: () => fileInputRef.current?.click(),
    })
    if (tabs.length >= 2) {
      utilities.push({
        type: 'button',
        text: isDiffMode ? 'Exit Diff' : 'Diff',
        variant: isDiffMode ? 'primary-button' : undefined,
        onClick: handleDiffToggle,
      })
    }
  }

  // Build SideNavigation items
  const navItems = tabs.map((tab) => ({
    type: 'link',
    text: tab.stig.title,
    href: `#${tab.id}`,
    info: (
      <Button
        variant="icon"
        iconName="close"
        ariaLabel={`Close ${tab.stig.title}`}
        onClick={(e) => {
          e.preventDefault()
          e.stopPropagation()
          removeTab(tab.id)
        }}
      />
    ),
  }))

  // Determine content
  let content
  if (!hasTabs) {
    content = (
      <StigLibrary
        onLoad={addStigFromBackend}
        onUploadTab={
          <DropZone onFilesLoad={addTabs} onLoadSample={addSampleTab} />
        }
      />
    )
  } else if (isDiffMode) {
    content = (
      <DiffView
        tabs={tabs}
        diffPair={diffPair}
        onSetDiffPair={setDiffPair}
        onExitDiff={() => setDiffPair(null)}
      />
    )
  } else if (activeTab) {
    content = (
      <STIGView
        tab={activeTab}
        onUpdateRule={(ruleId, updates) => updateRule(activeTabId, ruleId, updates)}
        onSetAssetInfo={(info) => setAssetInfo(activeTabId, info)}
        onSetSelectedRule={(ruleId) => setSelectedRule(activeTabId, ruleId)}
        onSetAllStatus={(status) => setAllStatus(activeTabId, status)}
        onAddFiles={addTabs}
      />
    )
  }

  return (
    <>
      <div id="h">
        <TopNavigation
          identity={{
            href: '#',
            title: 'STIG Viewer',
            logo: {
              src: 'data:image/svg+xml,' + encodeURIComponent(
                '<svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">'
                + '<rect width="40" height="40" rx="8" fill="#539fe5"/>'
                + '<path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1b2e"/>'
                + '<path d="M28 22l4 4-4 4" stroke="#0f1b2e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>'
                + '</svg>',
              ),
              alt: 'STIG Viewer',
            },
          }}
          utilities={utilities}
        />
      </div>

      {/* Hidden file input for Open File utility */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".xml,.ckl"
        multiple
        style={{ display: 'none' }}
        aria-hidden="true"
        tabIndex={-1}
        onChange={handleFileInput}
      />

      <AppLayout
        headerSelector="#h"
        contentType={!hasTabs ? 'table' : 'default'}
        navigationHide={!hasTabs || isDiffMode}
        navigationOpen={navOpen && hasTabs && !isDiffMode}
        onNavigationChange={({ detail }) => setNavOpen(detail.open)}
        navigationWidth={280}
        navigation={
          <SideNavigation
            header={{ text: 'Open STIGs', href: '#' }}
            activeHref={`#${activeTabId}`}
            onFollow={(e) => {
              e.preventDefault()
              const id = e.detail.href.slice(1)
              if (id && tabs.some((t) => t.id === id)) setActiveTab(id)
            }}
            items={navItems}
          />
        }
        toolsHide
        splitPanel={
          selectedRule && !isDiffMode ? (
            <SplitPanel
              header={selectedRule.stigId}
              closeBehavior="hide"
            >
              <RuleDetail
                rule={selectedRule}
                onUpdateRule={(updates) => updateRule(activeTabId, selectedRule.id, updates)}
                onClose={() => setSelectedRule(activeTabId, null)}
              />
            </SplitPanel>
          ) : undefined
        }
        splitPanelOpen={effectiveSplitOpen}
        splitPanelPreferences={{ position: 'side' }}
        onSplitPanelToggle={handleSplitPanelToggle}
        onSplitPanelPreferencesChange={() => {}}
        content={content}
      />
    </>
  )
}
