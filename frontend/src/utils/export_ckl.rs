use crate::constants::status_ckl;
use crate::model::Stig;

/// "CAT I" | "CAT II" | "CAT III" → XCCDF severity (unknown → "medium").
pub(crate) fn xccdf_severity(cat: &str) -> &'static str {
    match cat {
        "CAT I" => "high",
        "CAT III" => "low",
        _ => "medium",
    }
}

/// Escape the five XML special characters for text or attribute content.
pub(crate) fn esc_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn stig_data(name: &str, val: &str) -> String {
    format!(
        "        <STIG_DATA><VULN_ATTRIBUTE>{}</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{}</ATTRIBUTE_DATA></STIG_DATA>",
        esc_xml(name),
        esc_xml(val)
    )
}

fn si_data(name: &str, val: &str) -> String {
    format!(
        "        <SI_DATA><SID_NAME>{name}</SID_NAME><SID_DATA>{}</SID_DATA></SI_DATA>",
        esc_xml(val)
    )
}

/// Serialise a STIG + asset identity to DISA CKL XML.
pub fn export_ckl(stig: &Stig, hostname: &str, ip: &str, mac: &str, fqdn: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut push = |line: &str| lines.push(line.to_string());

    push(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    push("<!--DISA STIG Viewer :: Web STIG Tools Export-->");
    push("<CHECKLIST>");
    push("  <ASSET>");
    push("    <ROLE>None</ROLE>");
    push("    <ASSET_TYPE>Computing</ASSET_TYPE>");
    push(&format!("    <HOST_NAME>{}</HOST_NAME>", esc_xml(hostname)));
    push(&format!("    <HOST_IP>{}</HOST_IP>", esc_xml(ip)));
    push(&format!("    <HOST_MAC>{}</HOST_MAC>", esc_xml(mac)));
    push(&format!("    <HOST_FQDN>{}</HOST_FQDN>", esc_xml(fqdn)));
    push("    <TARGET_COMMENT></TARGET_COMMENT>");
    push("    <TECH_AREA></TECH_AREA>");
    push("    <TARGET_KEY></TARGET_KEY>");
    push("    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>");
    push("    <WEB_DB_SITE></WEB_DB_SITE>");
    push("    <WEB_DB_INSTANCE></WEB_DB_INSTANCE>");
    push("  </ASSET>");
    push("  <STIGS>");
    push("    <iSTIG>");
    push("      <STIG_INFO>");
    push(&si_data("title", &stig.title));
    push(&si_data("version", &stig.version));
    push(&si_data("releaseinfo", &stig.release_info));
    push("      </STIG_INFO>");

    for rule in &stig.rules {
        push("      <VULN>");
        push(&stig_data("Vuln_Num", &rule.stig_id));
        push(&stig_data("Severity", xccdf_severity(&rule.severity)));
        push(&stig_data("Group_Title", &rule.group_id));
        push(&stig_data("Rule_ID", &rule.id));
        push(&stig_data("Rule_Title", &rule.title));
        push(&stig_data("Vuln_Discuss", &rule.description));
        push(&stig_data("Check_Content", &rule.check_text));
        push(&stig_data("Fix_Text", &rule.fix_text));
        for cci in &rule.cci_ids {
            push(&stig_data("CCI_REF", cci));
        }
        push(&format!("        <STATUS>{}</STATUS>", status_ckl(&rule.status)));
        push(&format!(
            "        <FINDING_DETAILS>{}</FINDING_DETAILS>",
            esc_xml(&rule.finding_details)
        ));
        push(&format!("        <COMMENTS>{}</COMMENTS>", esc_xml(&rule.comments)));
        push("        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>");
        push("        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>");
        push("      </VULN>");
    }

    push("    </iSTIG>");
    push("  </STIGS>");
    push("</CHECKLIST>");

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Rule;

    #[test]
    fn escapes_all_five_xml_specials() {
        assert_eq!(esc_xml(r#"a&b<c>d"e'f"#), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(esc_xml("&amp;"), "&amp;amp;");
    }

    #[test]
    fn exports_the_exact_ckl_document() {
        let stig = Stig {
            title: "T & <Co>".into(),
            description: "not exported".into(),
            version: "3".into(),
            release_info: "Release: 1".into(),
            rules: vec![Rule {
                id: "SV-1r1_rule".into(),
                stig_id: "V-1".into(),
                group_id: "SRG-1".into(),
                title: "Rule \"one\"".into(),
                severity: "CAT I".into(),
                description: "Desc".into(),
                fix_text: "Fix".into(),
                check_text: "Check\n\nmore".into(),
                cci_ids: vec!["CCI-000001".into(), "CCI-000002".into()],
                status: "not_a_finding".into(),
                finding_details: "it's fine".into(),
                comments: String::new(),
                extra: Default::default(),
            }],
        };
        let expected = r#"<?xml version="1.0" encoding="UTF-8"?>
<!--DISA STIG Viewer :: Web STIG Tools Export-->
<CHECKLIST>
  <ASSET>
    <ROLE>None</ROLE>
    <ASSET_TYPE>Computing</ASSET_TYPE>
    <HOST_NAME>web&lt;01&gt;</HOST_NAME>
    <HOST_IP>10.0.0.1</HOST_IP>
    <HOST_MAC>aa:bb</HOST_MAC>
    <HOST_FQDN>web01.example.mil</HOST_FQDN>
    <TARGET_COMMENT></TARGET_COMMENT>
    <TECH_AREA></TECH_AREA>
    <TARGET_KEY></TARGET_KEY>
    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
    <WEB_DB_SITE></WEB_DB_SITE>
    <WEB_DB_INSTANCE></WEB_DB_INSTANCE>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>T &amp; &lt;Co&gt;</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>3</SID_DATA></SI_DATA>
        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>Release: 1</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SRG-1</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-1r1_rule</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Rule &quot;one&quot;</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Vuln_Discuss</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Desc</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Check

more</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Fix</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000001</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000002</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>NotAFinding</STATUS>
        <FINDING_DETAILS>it&apos;s fine</FINDING_DETAILS>
        <COMMENTS></COMMENTS>
        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>"#;
        assert_eq!(export_ckl(&stig, "web<01>", "10.0.0.1", "aa:bb", "web01.example.mil"), expected);
    }

    #[test]
    fn unknown_severity_and_status_fall_back() {
        let stig = Stig {
            rules: vec![Rule { severity: "bogus".into(), status: "weird".into(), ..Rule::default() }],
            ..Stig::default()
        };
        let xml = export_ckl(&stig, "", "", "", "");
        assert!(xml.contains("<VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>"));
        assert!(xml.contains("<STATUS>Not_Reviewed</STATUS>"));
        assert!(!xml.ends_with('\n'));
    }
}
