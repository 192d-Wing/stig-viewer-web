//! DISA CKL checklist → [`Stig`] parser.
//!
//! Only the STIG metadata and per-VULN data are read; the `<ASSET>` block
//! (host name / IP / MAC / FQDN) is ignored, exactly as in the original.

use super::parse_xccdf::{
    elements_by_tag_name, get_text_content, parse_document, remove_ascii_ci,
    strip_tags_and_collapse,
};
use crate::constants::severity_label;
use crate::model::{Rule, Stig};
use std::collections::HashMap;

const DEFAULT_TITLE: &str = "Imported Checklist";

fn clean_description(desc: &str) -> String {
    let out = remove_ascii_ci(desc, "<VulnDiscussion>");
    let out = remove_ascii_ci(&out, "</VulnDiscussion>");
    strip_tags_and_collapse(&out)
}

pub fn parse_ckl(xml: &str) -> Result<Stig, String> {
    // The browser DOMParser never throws: malformed XML yields an error
    // document with no CKL elements, which imports as an empty checklist.
    let Some(doc) = parse_document(xml) else {
        return Ok(Stig { title: DEFAULT_TITLE.to_string(), ..Stig::default() });
    };
    let root = doc.root();

    let mut title = String::new();
    let mut version = String::new();
    let mut release_info = String::new();

    if let Some(stig_info) = elements_by_tag_name(root, "STIG_INFO").next() {
        for si in elements_by_tag_name(stig_info, "SI_DATA") {
            let val = get_text_content(si, "SID_DATA");
            match get_text_content(si, "SID_NAME").as_str() {
                "title" => title = val,
                "version" => version = val,
                "releaseinfo" => release_info = val,
                _ => {}
            }
        }
    }

    let mut rules = Vec::new();

    for (i, vuln) in elements_by_tag_name(root, "VULN").enumerate() {
        // Last value wins for repeated attributes; CCI_REF accumulates.
        let mut attrs: HashMap<String, String> = HashMap::new();
        let mut cci_ids = Vec::new();

        for sd in elements_by_tag_name(vuln, "STIG_DATA") {
            let name = get_text_content(sd, "VULN_ATTRIBUTE");
            let val = get_text_content(sd, "ATTRIBUTE_DATA");
            if name == "CCI_REF" {
                cci_ids.push(val);
            } else {
                attrs.insert(name, val);
            }
        }
        // Present-but-empty attributes are kept (JS `??`, not `||`).
        let attr = |name: &str| attrs.get(name).cloned();

        let status = match get_text_content(vuln, "STATUS").as_str() {
            "NotAFinding" | "Not_A_Finding" => "not_a_finding",
            "Open" => "open",
            "Not_Applicable" | "NotApplicable" => "not_applicable",
            _ => "not_reviewed",
        };

        let severity_raw = attr("Severity").unwrap_or_else(|| "medium".to_string()).to_lowercase();

        rules.push(Rule {
            id: attr("Rule_ID").unwrap_or_else(|| format!("rule-{i}")),
            stig_id: attr("Vuln_Num").unwrap_or_else(|| format!("V-{}", 100_000 + i)),
            group_id: attr("Group_Title").unwrap_or_default(),
            title: attr("Rule_Title").unwrap_or_default(),
            severity: severity_label(&severity_raw).unwrap_or("CAT II").to_string(),
            description: clean_description(&attr("Vuln_Discuss").unwrap_or_default()),
            fix_text: attr("Fix_Text").or_else(|| attr("STIGRef")).unwrap_or_default(),
            check_text: attr("Check_Content").unwrap_or_default(),
            cci_ids,
            status: status.to_string(),
            finding_details: get_text_content(vuln, "FINDING_DETAILS"),
            comments: get_text_content(vuln, "COMMENTS"),
            extra: Default::default(),
        });
    }

    Ok(Stig {
        title: if title.is_empty() { DEFAULT_TITLE.to_string() } else { title },
        description: String::new(),
        version,
        release_info,
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::sample_stig::generate_sample_stig;
    use crate::utils::export_ckl::export_ckl;

    #[test]
    fn round_trips_the_sample_stig_through_export_ckl() {
        let original = generate_sample_stig();
        let xml = export_ckl(&original, "host", "10.0.0.1", "aa:bb", "host.example.mil");
        let parsed = parse_ckl(&xml).unwrap();

        // CKL carries no benchmark description; everything else survives.
        // (check_text keeps its inner newlines; the sample has no leading /
        // trailing whitespace or markup that trimming / cleaning would alter.)
        let expected = Stig { description: String::new(), ..original };
        assert_eq!(parsed, expected);
    }

    #[test]
    fn round_trips_xml_special_characters() {
        let mut stig = generate_sample_stig();
        stig.title = "R&D \"quoted\" 'single'".to_string();
        stig.rules.truncate(1);
        stig.rules[0].title = "a < b && c > d".to_string();
        stig.rules[0].comments = "5 > 3 & \"ok\"".to_string();
        stig.rules[0].finding_details = "line 1\nline 2".to_string();

        let parsed = parse_ckl(&export_ckl(&stig, "", "", "", "")).unwrap();
        assert_eq!(parsed.title, stig.title);
        assert_eq!(parsed.rules[0].title, stig.rules[0].title);
        assert_eq!(parsed.rules[0].comments, stig.rules[0].comments);
        assert_eq!(parsed.rules[0].finding_details, "line 1\nline 2");
    }

    fn vuln(body: &str) -> String {
        format!("<CHECKLIST><STIGS><iSTIG>{body}</iSTIG></STIGS></CHECKLIST>")
    }

    fn sd(name: &str, val: &str) -> String {
        format!(
            "<STIG_DATA><VULN_ATTRIBUTE>{name}</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{val}</ATTRIBUTE_DATA></STIG_DATA>"
        )
    }

    #[test]
    fn applies_defaults_when_data_is_missing() {
        let stig = parse_ckl(&vuln("<VULN/><VULN><STATUS> Bogus </STATUS></VULN>")).unwrap();
        assert_eq!(stig.title, "Imported Checklist");
        assert_eq!(stig.version, "");
        assert_eq!(stig.release_info, "");
        assert_eq!(stig.rules.len(), 2);
        let second = &stig.rules[1];
        assert_eq!(second.id, "rule-1");
        assert_eq!(second.stig_id, "V-100001");
        assert_eq!(second.severity, "CAT II");
        assert_eq!(second.status, "not_reviewed");
        assert!(second.cci_ids.is_empty());
        assert_eq!(second.group_id, "");
    }

    #[test]
    fn maps_every_status_spelling() {
        let cases = [
            ("NotAFinding", "not_a_finding"),
            ("Not_A_Finding", "not_a_finding"),
            ("Open", "open"),
            ("Not_Applicable", "not_applicable"),
            ("NotApplicable", "not_applicable"),
            ("Not_Reviewed", "not_reviewed"),
            ("open", "not_reviewed"),
            ("", "not_reviewed"),
        ];
        for (raw, expected) in cases {
            let xml = vuln(&format!("<VULN><STATUS>{raw}</STATUS></VULN>"));
            assert_eq!(parse_ckl(&xml).unwrap().rules[0].status, expected, "{raw}");
        }
    }

    #[test]
    fn reads_attributes_severity_and_fallbacks() {
        let body = format!(
            "<STIG_INFO>\
               <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA> My STIG </SID_DATA></SI_DATA>\
               <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>7</SID_DATA></SI_DATA>\
               <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>Release: 2</SID_DATA></SI_DATA>\
               <SI_DATA><SID_NAME>uuid</SID_NAME><SID_DATA>x</SID_DATA></SI_DATA>\
             </STIG_INFO>\
             <VULN>{}{}{}{}{}{}{}<STATUS>Open</STATUS><FINDING_DETAILS> fd </FINDING_DETAILS><COMMENTS>c</COMMENTS></VULN>\
             <VULN>{}{}</VULN>",
            sd("Vuln_Num", "V-1"),
            sd("Severity", "HIGH"),
            sd("Rule_ID", ""),
            sd("Vuln_Discuss", "&lt;VulnDiscussion&gt;Because  &lt;b&gt;reasons&lt;/b&gt;.&lt;/VulnDiscussion&gt;"),
            sd("STIGRef", "the ref"),
            sd("CCI_REF", "CCI-000001"),
            sd("CCI_REF", "CCI-000002"),
            sd("Severity", "low"),
            sd("Fix_Text", "fix") + &sd("STIGRef", "ref") + &sd("Fix_Text", "fix 2"),
        );
        let stig = parse_ckl(&vuln(&body)).unwrap();
        assert_eq!(stig.title, "My STIG");
        assert_eq!(stig.version, "7");
        assert_eq!(stig.release_info, "Release: 2");
        assert_eq!(stig.description, "");

        let first = &stig.rules[0];
        assert_eq!(first.stig_id, "V-1");
        assert_eq!(first.severity, "CAT I");
        assert_eq!(first.id, ""); // present but empty: no fallback
        assert_eq!(first.description, "Because reasons .");
        assert_eq!(first.fix_text, "the ref");
        assert_eq!(first.cci_ids, vec!["CCI-000001", "CCI-000002"]);
        assert_eq!(first.status, "open");
        assert_eq!(first.finding_details, "fd");
        assert_eq!(first.comments, "c");

        let second = &stig.rules[1];
        assert_eq!(second.severity, "CAT III");
        assert_eq!(second.fix_text, "fix 2"); // last duplicate wins
        assert_eq!(second.id, "rule-1");
    }

    #[test]
    fn malformed_xml_imports_as_an_empty_checklist() {
        let stig = parse_ckl("<CHECKLIST><VULN>").unwrap();
        assert_eq!(stig.title, "Imported Checklist");
        assert!(stig.rules.is_empty());
    }
}
