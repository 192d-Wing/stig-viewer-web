import { CCI_MAP } from '../constants/cciMap.js'

/**
 * Maps a rule's CCI IDs to their primary SP 800-53 control reference.
 * Returns the first matching control, or a joined list if multiple.
 */
function resolveControl(cciIds) {
  if (!cciIds || cciIds.length === 0) return ''
  const controls = cciIds
    // CCI_MAP is a static lookup; id comes from parsed XML — no prototype pollution risk.
    // eslint-disable-next-line security/detect-object-injection
    .map((id) => CCI_MAP[id]?.control ?? '')
    .filter(Boolean)
  const unique = [...new Set(controls)]
  return unique.join(', ')
}

function csvField(val) {
  const str = String(val ?? '')
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

const POAM_HEADERS = [
  'Control Vulnerability ID',
  'Office / Org',
  'Security Control Number (800-53)',
  'Weakness Name',
  'Weakness Description',
  'Weakness Detector Source',
  'Weakness Source Identifier',
  'Asset Identifier',
  'Point of Contact',
  'Resources Required',
  'Scheduled Completion Date',
  'Milestone with Completion Dates',
  'Milestone Changes',
  'Source Identifying Control Vulnerability',
  'Status',
  'Comments',
]

function buildRows(stig, assetInfo, includeNonReviewed) {
  return stig.rules
    .filter((r) => {
      if (r.status === 'not_a_finding' || r.status === 'not_applicable') return false
      if (!includeNonReviewed && r.status !== 'open') return false
      return true
    })
    .map((r) => [
      r.stigId,
      assetInfo?.hostname ?? '',
      resolveControl(r.cciIds),
      r.title,
      r.description,
      `DISA STIG: ${stig.title}`,
      r.id,
      assetInfo?.hostname ?? '',
      '',
      '',
      '',
      '',
      '',
      `${stig.title} ${stig.version ? `v${stig.version}` : ''} ${stig.releaseInfo ?? ''}`.trim(),
      r.status === 'open' ? 'Ongoing' : 'Submitted',
      r.comments,
    ])
}

/**
 * Generates a POAM CSV string.
 * @param {object} stig
 * @param {object} assetInfo
 * @param {boolean} includeNonReviewed - include Not_Reviewed findings in addition to Open
 */
export function exportPOAMCSV(stig, assetInfo, includeNonReviewed = false) {
  const rows = buildRows(stig, assetInfo, includeNonReviewed)
  const header = POAM_HEADERS.map(csvField).join(',')
  const body = rows.map((row) => row.map(csvField).join(',')).join('\n')
  return `${header}\n${body}`
}

/**
 * Generates a POAM JSON array.
 * @param {object} stig
 * @param {object} assetInfo
 * @param {boolean} includeNonReviewed
 */
export function exportPOAMJSON(stig, assetInfo, includeNonReviewed = false) {
  const rows = buildRows(stig, assetInfo, includeNonReviewed)
  return rows.map((row) =>
    // row is a fixed-length array built from POAM_HEADERS; index is numeric — no injection risk.
    // eslint-disable-next-line security/detect-object-injection
    Object.fromEntries(POAM_HEADERS.map((h, i) => [h, row[i] ?? ''])),
  )
}
