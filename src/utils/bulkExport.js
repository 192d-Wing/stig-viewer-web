import { exportCKL } from './exportCKL.js'
import { bulkExportPOAMCSV, bulkExportPOAMJSON } from './exportPOAM.js'
import { apiFetch, readApiError, UnauthorizedError } from '../api.js'

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

// Encode a string as base64 using window.btoa after UTF-8 encoding. btoa
// only handles Latin-1; CKL payloads can contain multi-byte characters.
function toBase64(str) {
  const bytes = new TextEncoder().encode(str)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return window.btoa(binary)
}

/**
 * Ask the server to sign one tab's CKL. Downloads both the .ckl and a
 * JSON sidecar containing the detached signature, the signing document,
 * and the key id. Resolves with the bundle so callers can display key-id
 * confirmation to the user.
 *
 * Throws UnauthorizedError on 401 so the auth hook can redirect; any other
 * error bubbles up for the caller to surface via toast.
 */
export async function downloadSignedCKL(tab) {
  const { hostname = '', ip = '', mac = '', fqdn = '' } = tab.assetInfo || {}
  const xml = exportCKL(tab.stig, hostname, ip, mac, fqdn)
  const base = sanitizeFilename(tab.stig.title || 'stig')

  const res = await apiFetch('/api/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      content: toBase64(xml),
      resource: tab.catalogId || tab.stig.title || null,
    }),
  })
  if (!res.ok) throw await readApiError(res)
  const bundle = await res.json()

  // Hand both files to the browser back-to-back. Tests rely on the .ckl
  // landing first so the sidecar has a matching companion.
  downloadBlob(new Blob([xml], { type: 'application/xml' }), `${base}.ckl`)
  await new Promise((r) => setTimeout(r, SEQUENTIAL_DOWNLOAD_DELAY_MS))
  downloadBlob(
    new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }),
    `${base}.ckl.sig.json`,
  )
  return bundle
}

// Re-export so UI code can narrow error handling.
export { UnauthorizedError }

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
