import { SEVERITY_MAP } from '../constants/severity.js'

function getTextContent(el, tagName) {
  if (!el) return ''
  const nodes = el.getElementsByTagName(tagName)
  return nodes.length > 0 ? nodes[0].textContent?.trim() ?? '' : ''
}

function getAttribute(el, attr) {
  return el?.getAttribute(attr) ?? ''
}

function cleanDescription(desc) {
  return desc
    .replace(/<VulnDiscussion>/gi, '')
    .replace(/<\/VulnDiscussion>/gi, '')
    .replace(/<FalsePositives>[\s\S]*?<\/FalsePositives>/gi, '')
    .replace(/<FalseNegatives>[\s\S]*?<\/FalseNegatives>/gi, '')
    .replace(/<Documentable>[\s\S]*?<\/Documentable>/gi, '')
    .replace(/<Mitigations>[\s\S]*?<\/Mitigations>/gi, '')
    .replace(/<SeverityOverrideGuidance>[\s\S]*?<\/SeverityOverrideGuidance>/gi, '')
    .replace(/<PotentialImpacts>[\s\S]*?<\/PotentialImpacts>/gi, '')
    .replace(/<ThirdPartyTools>[\s\S]*?<\/ThirdPartyTools>/gi, '')
    .replace(/<MitigationControl>[\s\S]*?<\/MitigationControl>/gi, '')
    .replace(/<Responsibility>[\s\S]*?<\/Responsibility>/gi, '')
    .replace(/<IAControls>[\s\S]*?<\/IAControls>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

export function parseXCCDF(xmlText) {
  const parser = new DOMParser()
  const doc = parser.parseFromString(xmlText, 'text/xml')

  const benchmarkEl =
    doc.getElementsByTagName('Benchmark')[0] ??
    doc.getElementsByTagNameNS('*', 'Benchmark')[0]
  if (!benchmarkEl) throw new Error('No Benchmark element found in XCCDF')

  const title = (
    getTextContent(benchmarkEl, 'title') ||
    getTextContent(benchmarkEl, 'Title') ||
    'Unknown STIG'
  ).replace(/^DPMS Target /, '')
  const description =
    getTextContent(benchmarkEl, 'description') ||
    getTextContent(benchmarkEl, 'Description') ||
    ''
  const version =
    getTextContent(benchmarkEl, 'version') ||
    getTextContent(benchmarkEl, 'Version') ||
    ''
  const releaseInfo =
    getTextContent(benchmarkEl, 'plain-text') ||
    getTextContent(benchmarkEl, 'release-info') ||
    ''

  const groupsLive =
    benchmarkEl.getElementsByTagName('Group').length > 0
      ? benchmarkEl.getElementsByTagName('Group')
      : benchmarkEl.getElementsByTagNameNS('*', 'Group')

  const rules = []
  for (const [i, group] of Array.from(groupsLive).entries()) {
    const groupId = getAttribute(group, 'id')
    const ruleEl =
      group.getElementsByTagName('Rule')[0] ??
      group.getElementsByTagNameNS('*', 'Rule')[0]
    if (!ruleEl) continue

    const ruleId = getAttribute(ruleEl, 'id')
    const severity = getAttribute(ruleEl, 'severity') || 'medium'
    const ruleTitle =
      getTextContent(ruleEl, 'title') || getTextContent(ruleEl, 'Title') || ''
    const ruleDesc =
      getTextContent(ruleEl, 'description') ||
      getTextContent(ruleEl, 'Description') ||
      ''
    const fixText =
      getTextContent(ruleEl, 'fixtext') ||
      getTextContent(ruleEl, 'fix') ||
      getTextContent(ruleEl, 'Fix') ||
      ''

    let checkText = ''
    const checkContentEls = ruleEl.getElementsByTagName('check-content')
    if (checkContentEls.length > 0) {
      checkText = checkContentEls[0].textContent?.trim() ?? ''
    }

    const cciIds = []
    for (const identEl of Array.from(ruleEl.getElementsByTagName('ident'))) {
      const val = identEl.textContent?.trim()
      if (val) cciIds.push(val)
    }

    const stigId = groupId || `V-${(100000 + i).toString()}`
    // SEVERITY_MAP keys are exactly 'high' | 'medium' | 'low' — no injection risk.
    // eslint-disable-next-line security/detect-object-injection
    const cat = SEVERITY_MAP[severity] ?? 'CAT II'

    rules.push({
      id: ruleId || `rule-${i}`,
      stigId,
      groupId,
      title: ruleTitle,
      severity: cat,
      description: cleanDescription(ruleDesc),
      fixText,
      checkText,
      cciIds,
      status: 'not_reviewed',
      findingDetails: '',
      comments: '',
    })
  }

  return { title, description, version, releaseInfo, rules }
}
