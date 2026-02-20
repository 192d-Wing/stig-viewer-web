import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import s from './StigLibrary.module.css'

const BACKEND = 'http://localhost:8080'

const CATEGORIES = ['Windows', 'Linux', 'Browser', 'Network']

/** Extract the numeric release from releaseInfo, e.g. "Release: 4 Benchmark …" → 4 */
function parseRelease(releaseInfo) {
  const m = releaseInfo?.match(/Release:\s*(\d+)/i)
  return m ? Number(m[1]) : 0
}

/**
 * Mark entries that are superseded by a newer version of the same STIG.
 * Two entries are "same STIG" when their titles match exactly.
 * The entry with the higher version (then higher release) wins.
 * Returns a Set of superseded entry IDs.
 */
function findSuperseded(catalog) {
  const byTitle = new Map()
  for (const entry of catalog) {
    const key = entry.title
    if (!byTitle.has(key)) byTitle.set(key, [])
    byTitle.get(key).push(entry)
  }

  const superseded = new Set()
  for (const entries of byTitle.values()) {
    if (entries.length < 2) continue
    // Sort descending: highest version first, then highest release
    const sorted = [...entries].sort((a, b) => {
      const vDiff = Number(b.version || 0) - Number(a.version || 0)
      if (vDiff !== 0) return vDiff
      return parseRelease(b.releaseInfo) - parseRelease(a.releaseInfo)
    })
    // Everything after the first is superseded
    for (let i = 1; i < sorted.length; i++) {
      superseded.add(sorted[i].id)
    }
  }
  return superseded
}

/** Comparator for sortable columns */
function comparator(col, dir) {
  const mul = dir === 'asc' ? 1 : -1
  return (a, b) => {
    let av, bv
    switch (col) {
      case 'category':
        av = a.category; bv = b.category
        return mul * av.localeCompare(bv)
      case 'title':
        av = a.title; bv = b.title
        return mul * av.localeCompare(bv)
      case 'version':
        av = Number(a.version || 0); bv = Number(b.version || 0)
        if (av !== bv) return mul * (av - bv)
        return mul * (parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo))
      case 'release':
        av = parseRelease(a.releaseInfo); bv = parseRelease(b.releaseInfo)
        return mul * (av - bv)
      case 'rules':
        return mul * (a.ruleCount - b.ruleCount)
      default:
        return 0
    }
  }
}

export default function StigLibrary({ onLoad, onUploadTab }) {
  const [activeTab, setActiveTab] = useState('library')
  const [catalog, setCatalog] = useState([])
  const [catalogLoading, setCatalogLoading] = useState(false)
  const [catalogError, setCatalogError] = useState(null)
  const [loadingId, setLoadingId] = useState(null)
  const [categoryFilter, setCategoryFilter] = useState(null)
  const [showSuperseded, setShowSuperseded] = useState(false)
  const [sortCol, setSortCol] = useState('title')
  const [sortDir, setSortDir] = useState('asc')

  // Add-to-library form state (single STIG)
  const [addFile, setAddFile] = useState(null)
  const [addId, setAddId] = useState('')
  const [addCategory, setAddCategory] = useState('Windows')
  const [addStatus, setAddStatus] = useState('idle') // idle | loading | success | error
  const [addResult, setAddResult] = useState(null)
  const fileInputRef = useRef(null)

  // Library bundle import state
  const [libFile, setLibFile] = useState(null)
  const [libStatus, setLibStatus] = useState('idle') // idle | loading | success | error
  const [libResult, setLibResult] = useState(null)
  const libFileInputRef = useRef(null)

  const fetchCatalog = useCallback(() => {
    setCatalogLoading(true)
    setCatalogError(null)
    let cancelled = false
    fetch(`${BACKEND}/api/catalog`)
      .then((r) => {
        if (!r.ok) throw new Error(`Backend returned ${r.status}`)
        return r.json()
      })
      .then((data) => { if (!cancelled) setCatalog(data) })
      .catch((err) => { if (!cancelled) setCatalogError(err.message) })
      .finally(() => { if (!cancelled) setCatalogLoading(false) })
    return () => { cancelled = true }
  }, [])

  useEffect(() => fetchCatalog(), [fetchCatalog])

  const supersededIds = useMemo(() => findSuperseded(catalog), [catalog])

  const displayList = useMemo(() => {
    let list = catalog
    if (categoryFilter) list = list.filter((e) => e.category === categoryFilter)
    if (!showSuperseded) list = list.filter((e) => !supersededIds.has(e.id))
    return [...list].sort(comparator(sortCol, sortDir))
  }, [catalog, categoryFilter, showSuperseded, supersededIds, sortCol, sortDir])

  const handleSort = useCallback((col) => {
    setSortCol((prev) => {
      if (prev === col) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
      } else {
        setSortDir('asc')
      }
      return col
    })
  }, [])

  const handleLoad = useCallback(
    async (id) => {
      setLoadingId(id)
      try {
        const r = await fetch(`${BACKEND}/api/stigs/${encodeURIComponent(id)}`)
        if (!r.ok) throw new Error(`Backend returned ${r.status}`)
        const stig = await r.json()
        onLoad(stig)
      } catch (err) {
        setCatalogError(`Failed to load STIG: ${err.message}`)
      } finally {
        setLoadingId(null)
      }
    },
    [onLoad],
  )

  const handleAddSubmit = useCallback(
    async (e) => {
      e.preventDefault()
      if (!addFile || !addId.trim()) return
      setAddStatus('loading')
      setAddResult(null)
      try {
        const body = new FormData()
        body.append('file', addFile)
        body.append('id', addId.trim())
        body.append('category', addCategory)
        const r = await fetch(`${BACKEND}/api/upload`, { method: 'POST', body })
        const json = await r.json()
        if (!r.ok) throw new Error(json?.message ?? `Server returned ${r.status}`)
        setAddResult(json)
        setAddStatus('success')
        // Reset form
        setAddFile(null)
        setAddId('')
        if (fileInputRef.current) fileInputRef.current.value = ''
        // Refresh catalog so the new entry appears immediately
        fetchCatalog()
      } catch (err) {
        setAddResult({ error: err.message })
        setAddStatus('error')
      }
    },
    [addFile, addId, addCategory, fetchCatalog],
  )

  const handleLibSubmit = useCallback(
    async (e) => {
      e.preventDefault()
      if (!libFile) return
      setLibStatus('loading')
      setLibResult(null)
      try {
        const body = new FormData()
        body.append('file', libFile)
        const r = await fetch(`${BACKEND}/api/upload/library`, { method: 'POST', body })
        const json = await r.json()
        if (!r.ok) throw new Error(json?.message ?? `Server returned ${r.status}`)
        setLibResult(json)
        setLibStatus('success')
        setLibFile(null)
        if (libFileInputRef.current) libFileInputRef.current.value = ''
        fetchCatalog()
      } catch (err) {
        setLibResult({ error: err.message })
        setLibStatus('error')
      }
    },
    [libFile, fetchCatalog],
  )

  const SortArrow = ({ col }) => {
    if (sortCol !== col) return <span className={s.sortIcon}>⇅</span>
    return <span className={s.sortIconActive}>{sortDir === 'asc' ? '↑' : '↓'}</span>
  }

  return (
    <div className={s.page}>
      <div className={s.panel}>
        {/* Brand */}
        <div className={s.brand}>
          <svg width="36" height="36" viewBox="0 0 40 40" fill="none" aria-hidden="true">
            <rect width="40" height="40" rx="8" fill="#c9a227" />
            <path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1115" />
            <path d="M28 22l4 4-4 4" stroke="#0f1115" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <h1 className={s.appName}>STIG Viewer</h1>
            <p className={s.appVersion}>WEB EDITION v3.0</p>
          </div>
        </div>

        {/* Tab switcher */}
        <div className={s.tabs} role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'library'}
            className={`${s.tab} ${activeTab === 'library' ? s.tabActive : ''}`}
            onClick={() => setActiveTab('library')}
          >
            STIG Library
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'add'}
            className={`${s.tab} ${activeTab === 'add' ? s.tabActive : ''}`}
            onClick={() => setActiveTab('add')}
          >
            Add to Library
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'upload'}
            className={`${s.tab} ${activeTab === 'upload' ? s.tabActive : ''}`}
            onClick={() => setActiveTab('upload')}
          >
            Open Local File
          </button>
        </div>

        {/* Library tab */}
        {activeTab === 'library' && (
          <div className={s.libraryBody}>
            <div className={s.toolRow}>
              <div className={s.chips} role="toolbar" aria-label="Filter by category">
                <button
                  type="button"
                  className={`${s.chip} ${categoryFilter === null ? s.chipActive : ''}`}
                  onClick={() => setCategoryFilter(null)}
                >
                  All
                </button>
                {CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    className={`${s.chip} ${categoryFilter === cat ? s.chipActive : ''}`}
                    onClick={() => setCategoryFilter(cat === categoryFilter ? null : cat)}
                  >
                    {cat}
                  </button>
                ))}
              </div>
              {supersededIds.size > 0 && (
                <label className={s.supersededToggle}>
                  <input
                    type="checkbox"
                    checked={showSuperseded}
                    onChange={(e) => setShowSuperseded(e.target.checked)}
                  />
                  Show superseded ({supersededIds.size})
                </label>
              )}
            </div>

            {catalogLoading && <p className={s.statusMsg}>Connecting to backend…</p>}
            {catalogError && <p className={s.errorMsg}>{catalogError}</p>}

            {!catalogLoading && !catalogError && displayList.length === 0 && (
              <p className={s.statusMsg}>
                {catalog.length === 0 ? (
                  <>
                    No STIGs cached yet — use the{' '}
                    <button
                      type="button"
                      className={s.inlineLink}
                      onClick={() => setActiveTab('add')}
                    >
                      Add to Library
                    </button>{' '}
                    tab to upload a STIG ZIP.
                  </>
                ) : (
                  'No STIGs match the current filters.'
                )}
              </p>
            )}

            {displayList.length > 0 && (
              <div className={s.tableWrapper}>
                <table className={s.table}>
                  <thead>
                    <tr>
                      <th className={`${s.th} ${s.sortable}`} onClick={() => handleSort('category')}>
                        Category <SortArrow col="category" />
                      </th>
                      <th className={`${s.th} ${s.sortable}`} onClick={() => handleSort('title')}>
                        Title <SortArrow col="title" />
                      </th>
                      <th className={`${s.thNum} ${s.sortable}`} onClick={() => handleSort('version')}>
                        Ver <SortArrow col="version" />
                      </th>
                      <th className={`${s.thNum} ${s.sortable}`} onClick={() => handleSort('release')}>
                        Rel <SortArrow col="release" />
                      </th>
                      <th className={`${s.thNum} ${s.sortable}`} onClick={() => handleSort('rules')}>
                        Rules <SortArrow col="rules" />
                      </th>
                      <th className={s.th} />
                    </tr>
                  </thead>
                  <tbody>
                    {displayList.map((entry) => {
                      const isSuperseded = supersededIds.has(entry.id)
                      return (
                        <tr key={entry.id} className={`${s.tr} ${isSuperseded ? s.trSuperseded : ''}`}>
                          <td className={s.td}>
                            <span className={`${s.catBadge} ${s[`cat${entry.category}`]}`}>
                              {entry.category}
                            </span>
                          </td>
                          <td className={s.td}>
                            {entry.title}
                            {isSuperseded && <span className={s.supersededBadge}>Superseded</span>}
                          </td>
                          <td className={`${s.td} ${s.mono}`}>{entry.version || '—'}</td>
                          <td className={`${s.td} ${s.mono}`}>{parseRelease(entry.releaseInfo) || '—'}</td>
                          <td className={`${s.td} ${s.mono}`}>{entry.ruleCount}</td>
                          <td className={s.td}>
                            <button
                              type="button"
                              className={s.loadBtn}
                              disabled={loadingId === entry.id}
                              onClick={() => handleLoad(entry.id)}
                              aria-label={`Load ${entry.title}`}
                            >
                              {loadingId === entry.id ? 'Loading…' : 'Load'}
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Add to Library tab */}
        {activeTab === 'add' && (
          <div className={s.addBody}>
            <p className={s.addHint}>
              Download a STIG ZIP from{' '}
              <a
                href="https://public.cyber.mil/stigs/downloads/"
                target="_blank"
                rel="noreferrer"
                className={s.extLink}
              >
                public.cyber.mil
              </a>
              , then upload it here to add it to the library.
            </p>

            <form className={s.addForm} onSubmit={handleAddSubmit}>
              <div className={s.formRow}>
                <label className={s.formLabel} htmlFor="add-file">
                  STIG ZIP file
                </label>
                <input
                  ref={fileInputRef}
                  id="add-file"
                  type="file"
                  accept=".zip"
                  required
                  className={s.formFile}
                  onChange={(e) => setAddFile(e.target.files?.[0] ?? null)}
                />
              </div>

              <div className={s.formRow}>
                <label className={s.formLabel} htmlFor="add-id">
                  ID <span className={s.formHint}>(slug, e.g. windows-11)</span>
                </label>
                <input
                  id="add-id"
                  type="text"
                  required
                  pattern="[A-Za-z0-9\-]+"
                  placeholder="e.g. windows-11"
                  className={s.formInput}
                  value={addId}
                  onChange={(e) => setAddId(e.target.value)}
                />
              </div>

              <div className={s.formRow}>
                <label className={s.formLabel} htmlFor="add-cat">
                  Category
                </label>
                <select
                  id="add-cat"
                  className={s.formSelect}
                  value={addCategory}
                  onChange={(e) => setAddCategory(e.target.value)}
                >
                  {CATEGORIES.map((c) => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              </div>

              <button
                type="submit"
                className={s.submitBtn}
                disabled={addStatus === 'loading'}
              >
                {addStatus === 'loading' ? 'Uploading…' : 'Upload to Library'}
              </button>
            </form>

            {addStatus === 'success' && addResult && (
              <div className={s.addSuccess}>
                <strong>{addResult.title}</strong> added —{' '}
                {addResult.ruleCount} rules ({addResult.version})
                <button
                  type="button"
                  className={s.inlineLink}
                  style={{ marginLeft: 12 }}
                  onClick={() => setActiveTab('library')}
                >
                  View in Library →
                </button>
              </div>
            )}
            {addStatus === 'error' && addResult && (
              <p className={s.errorMsg}>{addResult.error}</p>
            )}

            {/* Divider */}
            <div className={s.divider}>
              <span>or import full library bundle</span>
            </div>

            {/* Library bundle section */}
            <div className={s.addHint}>
              Download the all-in-one{' '}
              <strong>SRG-STIG Library</strong> bundle (~350 MB) from{' '}
              <a
                href="https://public.cyber.mil/stigs/downloads/"
                target="_blank"
                rel="noreferrer"
                className={s.extLink}
              >
                public.cyber.mil
              </a>
              . Uploading it will import every STIG automatically — IDs and
              categories are inferred from the file contents.
            </div>

            <form className={s.addForm} onSubmit={handleLibSubmit}>
              <div className={s.formRow}>
                <label className={s.formLabel} htmlFor="lib-file">
                  Library bundle ZIP
                </label>
                <input
                  ref={libFileInputRef}
                  id="lib-file"
                  type="file"
                  accept=".zip"
                  required
                  className={s.formFile}
                  onChange={(e) => setLibFile(e.target.files?.[0] ?? null)}
                />
              </div>

              <button
                type="submit"
                className={s.submitBtn}
                disabled={libStatus === 'loading'}
              >
                {libStatus === 'loading' ? 'Uploading & processing…' : 'Import Library Bundle'}
              </button>
            </form>

            {libStatus === 'success' && libResult && (
              <div className={s.addSuccess}>
                Imported <strong>{libResult.imported}</strong> STIGs
                {libResult.errors > 0 && (
                  <span className={s.libErrNote}> ({libResult.errors} skipped)</span>
                )}
                <button
                  type="button"
                  className={s.inlineLink}
                  style={{ marginLeft: 12 }}
                  onClick={() => setActiveTab('library')}
                >
                  View in Library →
                </button>
              </div>
            )}
            {libStatus === 'error' && libResult && (
              <p className={s.errorMsg}>{libResult.error}</p>
            )}
          </div>
        )}

        {/* Open Local File tab */}
        {activeTab === 'upload' && (
          <div className={s.uploadBody}>
            {onUploadTab}
          </div>
        )}
      </div>
    </div>
  )
}
