const SEV_MAP = { 'CAT I': 'high', 'CAT II': 'medium', 'CAT III': 'low' }

function escXml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}

export function exportXCCDF(stig) {
  const lines = []

  lines.push('<?xml version="1.0" encoding="utf-8"?>')
  lines.push('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"')
  lines.push(`  id="xccdf_mil.disa.stig_benchmark_${escXml(stig.title.replace(/\s+/g, '_'))}"`)
  lines.push('  xml:lang="en">')
  lines.push(`  <title>${escXml(stig.title)}</title>`)
  if (stig.description) {
    lines.push(`  <description>${escXml(stig.description)}</description>`)
  }
  if (stig.version) {
    lines.push(`  <version>${escXml(stig.version)}</version>`)
  }
  if (stig.releaseInfo) {
    lines.push(`  <plain-text id="release-info">${escXml(stig.releaseInfo)}</plain-text>`)
  }

  for (const rule of stig.rules) {
    const severity = SEV_MAP[rule.severity] ?? 'medium'
    const groupId = rule.stigId || rule.groupId || 'V-000000'

    lines.push(`  <Group id="${escXml(groupId)}">`)
    lines.push(`    <title>${escXml(rule.groupId || groupId)}</title>`)
    lines.push(`    <Rule id="${escXml(rule.id)}" severity="${severity}">`)
    lines.push(`      <title>${escXml(rule.title)}</title>`)
    lines.push(`      <description>&lt;VulnDiscussion&gt;${escXml(rule.description)}&lt;/VulnDiscussion&gt;</description>`)
    if (rule.fixText) {
      lines.push(`      <fixtext>${escXml(rule.fixText)}</fixtext>`)
    }
    if (rule.checkText) {
      lines.push('      <check system="C-0_chk">')
      lines.push(`        <check-content>${escXml(rule.checkText)}</check-content>`)
      lines.push('      </check>')
    }
    for (const cci of rule.cciIds) {
      lines.push(`      <ident system="http://cyber.mil/cci">${escXml(cci)}</ident>`)
    }
    lines.push('    </Rule>')
    lines.push('  </Group>')
  }

  lines.push('</Benchmark>')
  return lines.join('\n')
}
