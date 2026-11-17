use super::export_ckl::{esc_xml, xccdf_severity};
use super::parse_xccdf::is_js_whitespace;
use crate::model::Stig;

/// `title.replace(/\s+/g, '_')` — each whitespace run becomes one underscore.
fn benchmark_id_suffix(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    let mut in_whitespace = false;
    for c in title.chars() {
        if is_js_whitespace(c) {
            if !in_whitespace {
                out.push('_');
            }
            in_whitespace = true;
        } else {
            out.push(c);
            in_whitespace = false;
        }
    }
    out
}

/// First non-empty candidate (the JS `a || b || c` chain).
fn first_non_empty<'a>(candidates: &[&'a str]) -> &'a str {
    candidates.iter().copied().find(|s| !s.is_empty()).unwrap_or("")
}

pub fn export_xccdf(stig: &Stig) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(r#"<?xml version="1.0" encoding="utf-8"?>"#.to_string());
    lines.push(r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2""#.to_string());
    lines.push(format!(
        r#"  id="xccdf_mil.disa.stig_benchmark_{}""#,
        esc_xml(&benchmark_id_suffix(&stig.title))
    ));
    lines.push(r#"  xml:lang="en">"#.to_string());
    lines.push(format!("  <title>{}</title>", esc_xml(&stig.title)));
    if !stig.description.is_empty() {
        lines.push(format!("  <description>{}</description>", esc_xml(&stig.description)));
    }
    if !stig.version.is_empty() {
        lines.push(format!("  <version>{}</version>", esc_xml(&stig.version)));
    }
    if !stig.release_info.is_empty() {
        lines.push(format!(
            r#"  <plain-text id="release-info">{}</plain-text>"#,
            esc_xml(&stig.release_info)
        ));
    }

    for rule in &stig.rules {
        let severity = xccdf_severity(&rule.severity);
        let group_id = first_non_empty(&[&rule.stig_id, &rule.group_id, "V-000000"]);

        lines.push(format!(r#"  <Group id="{}">"#, esc_xml(group_id)));
        lines.push(format!(
            "    <title>{}</title>",
            esc_xml(first_non_empty(&[&rule.group_id, group_id]))
        ));
        lines.push(format!(r#"    <Rule id="{}" severity="{severity}">"#, esc_xml(&rule.id)));
        lines.push(format!("      <title>{}</title>", esc_xml(&rule.title)));
        lines.push(format!(
            "      <description>&lt;VulnDiscussion&gt;{}&lt;/VulnDiscussion&gt;</description>",
            esc_xml(&rule.description)
        ));
        if !rule.fix_text.is_empty() {
            lines.push(format!("      <fixtext>{}</fixtext>", esc_xml(&rule.fix_text)));
        }
        if !rule.check_text.is_empty() {
            lines.push(r#"      <check system="C-0_chk">"#.to_string());
            lines.push(format!(
                "        <check-content>{}</check-content>",
                esc_xml(&rule.check_text)
            ));
            lines.push("      </check>".to_string());
        }
        for cci in &rule.cci_ids {
            lines.push(format!(
                r#"      <ident system="http://cyber.mil/cci">{}</ident>"#,
                esc_xml(cci)
            ));
        }
        lines.push("    </Rule>".to_string());
        lines.push("  </Group>".to_string());
    }

    lines.push("</Benchmark>".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::sample_stig::generate_sample_stig;
    use crate::model::Rule;
    use crate::utils::parse_xccdf::parse_xccdf;

    #[test]
    fn exports_the_exact_xccdf_document() {
        let stig = Stig {
            title: "My  STIG\t& <Co>".into(),
            description: "About".into(),
            version: "2".into(),
            release_info: "Release: 1".into(),
            rules: vec![
                Rule {
                    id: "SV-1r1_rule".into(),
                    stig_id: "V-1".into(),
                    group_id: "SRG-1".into(),
                    title: "Title".into(),
                    severity: "CAT III".into(),
                    description: "Why \"this\" matters".into(),
                    fix_text: "Fix".into(),
                    check_text: "Check".into(),
                    cci_ids: vec!["CCI-000001".into()],
                    ..Rule::default()
                },
                Rule { id: "r2".into(), severity: "nope".into(), ..Rule::default() },
                Rule { id: "r3".into(), group_id: "G-3".into(), severity: "CAT I".into(), ..Rule::default() },
            ],
        };
        let expected = r#"<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"
  id="xccdf_mil.disa.stig_benchmark_My_STIG_&amp;_&lt;Co&gt;"
  xml:lang="en">
  <title>My  STIG	&amp; &lt;Co&gt;</title>
  <description>About</description>
  <version>2</version>
  <plain-text id="release-info">Release: 1</plain-text>
  <Group id="V-1">
    <title>SRG-1</title>
    <Rule id="SV-1r1_rule" severity="low">
      <title>Title</title>
      <description>&lt;VulnDiscussion&gt;Why &quot;this&quot; matters&lt;/VulnDiscussion&gt;</description>
      <fixtext>Fix</fixtext>
      <check system="C-0_chk">
        <check-content>Check</check-content>
      </check>
      <ident system="http://cyber.mil/cci">CCI-000001</ident>
    </Rule>
  </Group>
  <Group id="V-000000">
    <title>V-000000</title>
    <Rule id="r2" severity="medium">
      <title></title>
      <description>&lt;VulnDiscussion&gt;&lt;/VulnDiscussion&gt;</description>
    </Rule>
  </Group>
  <Group id="G-3">
    <title>G-3</title>
    <Rule id="r3" severity="high">
      <title></title>
      <description>&lt;VulnDiscussion&gt;&lt;/VulnDiscussion&gt;</description>
    </Rule>
  </Group>
</Benchmark>"#;
        assert_eq!(export_xccdf(&stig), expected);
    }

    #[test]
    fn omits_empty_optional_header_elements() {
        let xml = export_xccdf(&Stig { title: "T".into(), ..Stig::default() });
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
             <Benchmark xmlns=\"http://checklists.nist.gov/xccdf/1.2\"\n  \
             id=\"xccdf_mil.disa.stig_benchmark_T\"\n  xml:lang=\"en\">\n  <title>T</title>\n</Benchmark>"
        );
    }

    #[test]
    fn round_trips_through_parse_xccdf() {
        let original = generate_sample_stig();
        let parsed = parse_xccdf(&export_xccdf(&original)).unwrap();

        // XCCDF has no review state, and the Group id is the STIG id on re-import.
        let mut expected = original;
        for rule in &mut expected.rules {
            rule.group_id = rule.stig_id.clone();
            rule.status = "not_reviewed".into();
            rule.finding_details.clear();
            rule.comments.clear();
        }
        assert_eq!(parsed, expected);
    }
}
