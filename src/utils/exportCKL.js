import { STATUS_CKL_MAP } from '../constants/status.js'

const SEV_MAP = { 'CAT I': 'high', 'CAT II': 'medium', 'CAT III': 'low' }

function escXml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

export function exportCKL(stig, hostname = '', ip = '', mac = '', fqdn = '') {
  const lines = []

  lines.push('<?xml version="1.0" encoding="UTF-8"?>')
  lines.push('<!--DISA STIG Viewer :: Web STIG Viewer Export-->')
  lines.push('<CHECKLIST>')
  lines.push('  <ASSET>')
  lines.push('    <ROLE>None</ROLE>')
  lines.push('    <ASSET_TYPE>Computing</ASSET_TYPE>')
  lines.push(`    <HOST_NAME>${escXml(hostname)}</HOST_NAME>`)
  lines.push(`    <HOST_IP>${escXml(ip)}</HOST_IP>`)
  lines.push(`    <HOST_MAC>${escXml(mac)}</HOST_MAC>`)
  lines.push(`    <HOST_FQDN>${escXml(fqdn)}</HOST_FQDN>`)
  lines.push('    <TARGET_COMMENT></TARGET_COMMENT>')
  lines.push('    <TECH_AREA></TECH_AREA>')
  lines.push('    <TARGET_KEY></TARGET_KEY>')
  lines.push('    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>')
  lines.push('    <WEB_DB_SITE></WEB_DB_SITE>')
  lines.push('    <WEB_DB_INSTANCE></WEB_DB_INSTANCE>')
  lines.push('  </ASSET>')
  lines.push('  <STIGS>')
  lines.push('    <iSTIG>')
  lines.push('      <STIG_INFO>')
  lines.push(
    `        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>${escXml(stig.title)}</SID_DATA></SI_DATA>`,
  )
  lines.push(
    `        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>${escXml(stig.version)}</SID_DATA></SI_DATA>`,
  )
  lines.push(
    `        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>${escXml(stig.releaseInfo)}</SID_DATA></SI_DATA>`,
  )
  lines.push('      </STIG_INFO>')

  for (const rule of stig.rules) {
    lines.push('      <VULN>')
    const sd = (name, val) =>
      `        <STIG_DATA><VULN_ATTRIBUTE>${escXml(name)}</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(val)}</ATTRIBUTE_DATA></STIG_DATA>`

    lines.push(sd('Vuln_Num', rule.stigId))
    lines.push(sd('Severity', SEV_MAP[rule.severity] ?? 'medium'))
    lines.push(sd('Group_Title', rule.groupId))
    lines.push(sd('Rule_ID', rule.id))
    lines.push(sd('Rule_Title', rule.title))
    lines.push(sd('Vuln_Discuss', rule.description))
    lines.push(sd('Check_Content', rule.checkText))
    lines.push(sd('Fix_Text', rule.fixText))
    for (const cci of rule.cciIds) {
      lines.push(sd('CCI_REF', cci))
    }
    lines.push(`        <STATUS>${STATUS_CKL_MAP[rule.status] ?? 'Not_Reviewed'}</STATUS>`)
    lines.push(`        <FINDING_DETAILS>${escXml(rule.findingDetails)}</FINDING_DETAILS>`)
    lines.push(`        <COMMENTS>${escXml(rule.comments)}</COMMENTS>`)
    lines.push('        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>')
    lines.push('        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>')
    lines.push('      </VULN>')
  }

  lines.push('    </iSTIG>')
  lines.push('  </STIGS>')
  lines.push('</CHECKLIST>')

  return lines.join('\n')
}
