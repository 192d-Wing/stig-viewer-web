import { describe, it, expect } from 'vitest'
import { parseCKL } from '../parseCKL.js'

const CKL_FIXTURE = `<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Test STIG</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>2</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>Release: 5</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1000</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-1000r1_rule</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Rule one title</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE><ATTRIBUTE_DATA>&lt;VulnDiscussion&gt;Why this matters&lt;/VulnDiscussion&gt;</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Apply the fix</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Verify setting</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000001</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000002</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>NotAFinding</STATUS>
        <FINDING_DETAILS>all good</FINDING_DETAILS>
        <COMMENTS>reviewed 2025</COMMENTS>
      </VULN>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1001</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-1001r1_rule</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Rule two title</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>low</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>`

describe('parseCKL', () => {
  it('extracts STIG-level title, version, and releaseInfo', () => {
    const stig = parseCKL(CKL_FIXTURE)
    expect(stig.title).toBe('Test STIG')
    expect(stig.version).toBe('2')
    expect(stig.releaseInfo).toBe('Release: 5')
  })

  it('parses two rules with the correct ids and titles', () => {
    const stig = parseCKL(CKL_FIXTURE)
    expect(stig.rules).toHaveLength(2)
    expect(stig.rules[0].stigId).toBe('V-1000')
    expect(stig.rules[0].id).toBe('SV-1000r1_rule')
    expect(stig.rules[0].title).toBe('Rule one title')
    expect(stig.rules[1].stigId).toBe('V-1001')
  })

  it('maps severity strings to CAT labels', () => {
    const stig = parseCKL(CKL_FIXTURE)
    expect(stig.rules[0].severity).toBe('CAT I')
    expect(stig.rules[1].severity).toBe('CAT III')
  })

  it('maps CKL STATUS values to internal status', () => {
    const stig = parseCKL(CKL_FIXTURE)
    expect(stig.rules[0].status).toBe('not_a_finding')
    expect(stig.rules[1].status).toBe('open')
  })

  it('collects multiple CCI_REF values into cciIds array', () => {
    const stig = parseCKL(CKL_FIXTURE)
    expect(stig.rules[0].cciIds).toEqual(['CCI-000001', 'CCI-000002'])
  })

  it('strips VulnDiscussion tags from the description', () => {
    const stig = parseCKL(CKL_FIXTURE)
    expect(stig.rules[0].description).toBe('Why this matters')
  })

  it('preserves finding details and comments', () => {
    const stig = parseCKL(CKL_FIXTURE)
    expect(stig.rules[0].findingDetails).toBe('all good')
    expect(stig.rules[0].comments).toBe('reviewed 2025')
  })

  it('defaults to not_reviewed when STATUS is missing', () => {
    const noStatusXml = CKL_FIXTURE.replace('<STATUS>Open</STATUS>', '')
    const parsed = parseCKL(noStatusXml)
    expect(parsed.rules[1].status).toBe('not_reviewed')
  })
})
