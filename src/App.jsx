import { useStigTabs } from './hooks/useStigTabs.js'
import DropZone from './components/DropZone.jsx'
import StigLibrary from './components/StigLibrary.jsx'
import TabBar from './components/TabBar.jsx'
import STIGView from './components/STIGView.jsx'
import DiffView from './components/DiffView.jsx'
import s from './App.module.css'

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

  // Landing page — no tabs loaded yet
  if (tabs.length === 0) {
    return (
      <StigLibrary
        onLoad={addStigFromBackend}
        onUploadTab={
          <DropZone onFilesLoad={addTabs} onLoadSample={addSampleTab} />
        }
      />
    )
  }

  const activeTab = tabs.find((t) => t.id === activeTabId)
  const isDiffMode = diffPair !== null

  const handleDiffToggle = (pair) => {
    if (pair === null) {
      setDiffPair(null)
    } else {
      const defaultA = tabs[0]?.id ?? null
      const defaultB = tabs[1]?.id ?? null
      setDiffPair([defaultA, defaultB])
    }
  }

  return (
    <div className={s.app}>
      <TabBar
        tabs={tabs}
        activeTabId={activeTabId}
        diffPair={diffPair}
        onActivate={setActiveTab}
        onClose={removeTab}
        onAddFiles={addTabs}
        onDiff={handleDiffToggle}
      />

      {isDiffMode ? (
        <DiffView
          tabs={tabs}
          diffPair={diffPair}
          onSetDiffPair={setDiffPair}
          onExitDiff={() => setDiffPair(null)}
        />
      ) : (
        activeTab && (
          <STIGView
            tab={activeTab}
            onUpdateRule={(ruleId, updates) => updateRule(activeTabId, ruleId, updates)}
            onSetAssetInfo={(info) => setAssetInfo(activeTabId, info)}
            onSetSelectedRule={(ruleId) => setSelectedRule(activeTabId, ruleId)}
            onSetAllStatus={(status) => setAllStatus(activeTabId, status)}
            onAddFiles={addTabs}
          />
        )
      )}
    </div>
  )
}
