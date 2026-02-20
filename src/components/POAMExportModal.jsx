import { useState, useCallback } from 'react'
import { exportPOAMCSV, exportPOAMJSON } from '../utils/exportPOAM.js'
import s from './POAMExportModal.module.css'

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function POAMExportModal({ show, onClose, stig, assetInfo }) {
  const [includeNonReviewed, setIncludeNonReviewed] = useState(false)

  const baseName = stig.title.replace(/[^a-zA-Z0-9]/g, '_')

  const handleCSV = useCallback(() => {
    const csv = exportPOAMCSV(stig, assetInfo, includeNonReviewed)
    downloadBlob(csv, `${baseName}_POAM.csv`, 'text/csv;charset=utf-8;')
  }, [stig, assetInfo, includeNonReviewed, baseName])

  const handleJSON = useCallback(() => {
    const rows = exportPOAMJSON(stig, assetInfo, includeNonReviewed)
    const json = JSON.stringify(rows, null, 2)
    downloadBlob(json, `${baseName}_POAM.json`, 'application/json')
  }, [stig, assetInfo, includeNonReviewed, baseName])

  if (!show) return null

  const openCount = stig.rules.filter((r) => r.status === 'open').length
  const pendingCount = stig.rules.filter((r) => r.status === 'not_reviewed').length

  return (
    <div
      className={s.backdrop}
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Export POAM"
    >
      <div className={s.modal} onClick={(e) => e.stopPropagation()}>
        <h2 className={s.title}>Export POA&amp;M</h2>

        {/* Counts */}
        <div className={s.counts}>
          <span className={s.countOpen}>{openCount} Open findings</span>
          <span className={s.countPending}>{pendingCount} Not Reviewed</span>
        </div>

        {/* Scope toggle */}
        <fieldset className={s.fieldset}>
          <legend className={s.legend}>Scope</legend>
          <label className={s.radioLabel}>
            <input
              type="radio"
              name="poam-scope"
              checked={!includeNonReviewed}
              onChange={() => setIncludeNonReviewed(false)}
              className={s.radio}
            />
            Open findings only ({openCount} items)
          </label>
          <label className={s.radioLabel}>
            <input
              type="radio"
              name="poam-scope"
              checked={includeNonReviewed}
              onChange={() => setIncludeNonReviewed(true)}
              className={s.radio}
            />
            Open + Not Reviewed ({openCount + pendingCount} items)
          </label>
        </fieldset>

        {/* Format buttons */}
        <div className={s.actions}>
          <button type="button" onClick={onClose} className={s.cancelBtn}>
            Cancel
          </button>
          <button type="button" onClick={handleJSON} className={s.exportBtn}>
            Download JSON
          </button>
          <button type="button" onClick={handleCSV} className={s.primaryBtn}>
            Download CSV
          </button>
        </div>
      </div>
    </div>
  )
}
