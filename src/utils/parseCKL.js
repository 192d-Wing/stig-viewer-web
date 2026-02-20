import { SEVERITY_MAP } from '../constants/severity.js'

function getTextContent(el, tagName) {
  if (!el) return ''
  const nodes = el.getElementsByTagName(tagName)
  return nodes.length > 0 ? nodes[0].textContent?.trim() ?? '' : ''
}

function cleanDescription(desc) {
  return desc
    .replace(/<VulnDiscussion>/gi, '')
    .replace(/<\/VulnDiscussion>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

export function parseCKL(xmlText) {
  const parser = new DOMParser()
  const doc = parser.parseFromString(xmlText, 'text/xml')

  const stigInfoEl = doc.getElementsByTagName('STIG_INFO')[0]
  let title = ''
  let version = ''
  let releaseInfo = ''

  if (stigInfoEl) {
    for (const siEl of Array.from(stigInfoEl.getElementsByTagName('SI_DATA'))) {
      const name = getTextContent(siEl, 'SID_NAME')
      const val = getTextContent(siEl, 'SID_DATA')
      if (name === 'title') title = val
      else if (name === 'version') version = val
      else if (name === 'releaseinfo') releaseInfo = val
    }
  }

  const rules = []

  for (const [i, vuln] of Array.from(doc.getElementsByTagName('VULN')).entries()) {
    const attrs = {}

    for (const sdEl of Array.from(vuln.getElementsByTagName('STIG_DATA'))) {
      const name = getTextContent(sdEl, 'VULN_ATTRIBUTE')
      const val = getTextContent(sdEl, 'ATTRIBUTE_DATA')
      if (name === 'CCI_REF') {
        if (!attrs.cciIds) attrs.cciIds = []
        attrs.cciIds.push(val)
      } else {
        // Bracket write keyed by parsed XML string; controlled input from user-loaded file.
        // eslint-disable-next-line security/detect-object-injection
        attrs[name] = val
      }
    }

    const rawStatus = getTextContent(vuln, 'STATUS')
    let status = 'not_reviewed'
    if (rawStatus === 'NotAFinding' || rawStatus === 'Not_A_Finding') status = 'not_a_finding'
    else if (rawStatus === 'Open') status = 'open'
    else if (rawStatus === 'Not_Applicable' || rawStatus === 'NotApplicable') status = 'not_applicable'

    const severityRaw = (attrs['Severity'] ?? 'medium').toLowerCase()
    // SEVERITY_MAP has exactly three keys: 'high' | 'medium' | 'low' — no injection risk.
    // eslint-disable-next-line security/detect-object-injection
    const cat = SEVERITY_MAP[severityRaw] ?? 'CAT II'

    rules.push({
      id: attrs['Rule_ID'] ?? `rule-${i}`,
      stigId: attrs['Vuln_Num'] ?? `V-${100000 + i}`,
      groupId: attrs['Group_Title'] ?? '',
      title: attrs['Rule_Title'] ?? '',
      severity: cat,
      description: cleanDescription(attrs['Vuln_Discuss'] ?? ''),
      fixText: attrs['Fix_Text'] ?? attrs['STIGRef'] ?? '',
      checkText: attrs['Check_Content'] ?? '',
      cciIds: attrs.cciIds ?? [],
      status,
      findingDetails: getTextContent(vuln, 'FINDING_DETAILS'),
      comments: getTextContent(vuln, 'COMMENTS'),
    })
  }

  return {
    title: title || 'Imported Checklist',
    description: '',
    version,
    releaseInfo,
    rules,
  }
}
