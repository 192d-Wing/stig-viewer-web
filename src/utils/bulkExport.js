import { exportCKL } from './exportCKL.js'
import { bulkExportPOAMCSV, bulkExportPOAMJSON } from './exportPOAM.js'

// Delay between sequential downloads so browsers don't suppress the later
// ones as "automatic downloads blocked".
const SEQUENTIAL_DOWNLOAD_DELAY_MS = 150

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_')
}

/**
 * Download one .ckl per tab, sequentially. Resolves when all files have been
 * handed to the browser.
 */
export async function downloadAllCKL(tabs) {
  for (let i = 0; i < tabs.length; i++) {
    // Bracket access against an array we iterate explicitly — no injection risk.
    // eslint-disable-next-line security/detect-object-injection
    const tab = tabs[i]
    const { hostname = '', ip = '', mac = '', fqdn = '' } = tab.assetInfo || {}
    const xml = exportCKL(tab.stig, hostname, ip, mac, fqdn)
    const blob = new Blob([xml], { type: 'application/xml' })
    const base = sanitizeFilename(tab.stig.title || 'stig')
    downloadBlob(blob, `${base}.ckl`)
    if (i < tabs.length - 1) {
      await new Promise((r) => setTimeout(r, SEQUENTIAL_DOWNLOAD_DELAY_MS))
    }
  }
}

/**
 * Download a single combined POAM file containing open findings from every tab.
 * `format` is 'csv' or 'json'.
 */
export function downloadCombinedPOAM(tabs, format = 'csv', includeNonReviewed = false) {
  if (format === 'json') {
    const arr = bulkExportPOAMJSON(tabs, includeNonReviewed)
    downloadBlob(
      new Blob([JSON.stringify(arr, null, 2)], { type: 'application/json' }),
      'combined-poam.json',
    )
    return
  }
  const csv = bulkExportPOAMCSV(tabs, includeNonReviewed)
  downloadBlob(new Blob([csv], { type: 'text/csv' }), 'combined-poam.csv')
}
