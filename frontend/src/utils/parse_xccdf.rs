//! XCCDF benchmark → [`Stig`] parser.
//!
//! The original implementation ran on the browser `DOMParser`; this one uses
//! `roxmltree` so it is testable natively. The small DOM shims below
//! reproduce the DOM semantics the parsers rely on (`getElementsByTagName`,
//! `textContent`, `String.prototype.trim`) and are shared with `parse_ckl`.

use crate::constants::severity_label;
use crate::model::{Rule, Stig};
use roxmltree::{Document, Node, ParsingOptions};

// ── DOM / JS string shims ────────────────────────────────────────────────

/// ECMAScript `WhiteSpace` + `LineTerminator` — what `\s` and `trim()` match.
/// (Differs from `char::is_whitespace`: includes U+FEFF, excludes U+0085.)
pub(crate) fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ' | '\u{A0}' | '\u{1680}'
            | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}'
            | '\u{3000}' | '\u{FEFF}'
    )
}

/// `String.prototype.trim`.
pub(crate) fn js_trim(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// Parse like `DOMParser.parseFromString(text, 'text/xml')`. `None` stands in
/// for the `<parsererror>` document the browser returns for malformed input.
pub(crate) fn parse_document(xml: &str) -> Option<Document<'_>> {
    let xml = xml.strip_prefix('\u{FEFF}').unwrap_or(xml);
    let options = ParsingOptions { allow_dtd: true, ..ParsingOptions::default() };
    Document::parse_with_options(xml, options).ok()
}

/// Whether the element's *qualified* name equals `tag`, i.e. the local name
/// matches and the element was written without a namespace prefix.
fn has_qualified_name(node: Node, tag: &str) -> bool {
    if !node.is_element() || node.tag_name().name() != tag {
        return false;
    }
    match node.tag_name().namespace() {
        None => true,
        // roxmltree does not keep the source prefix; an element whose
        // namespace is the in-scope default namespace is unprefixed.
        Some(ns) => node.default_namespace() == Some(ns),
    }
}

/// `scope.getElementsByTagName(tag)`: descendants at any depth, in document
/// order, matched by qualified name. The scope node itself is excluded
/// (pass the document root node to search the whole document).
pub(crate) fn elements_by_tag_name<'a, 'input>(
    scope: Node<'a, 'input>,
    tag: &'a str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    scope.descendants().skip(1).filter(move |n| has_qualified_name(*n, tag))
}

/// `scope.getElementsByTagNameNS('*', local)`: any namespace, any prefix.
fn elements_by_local_name<'a, 'input>(
    scope: Node<'a, 'input>,
    local: &'a str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    scope
        .descendants()
        .skip(1)
        .filter(move |n| n.is_element() && n.tag_name().name() == local)
}

/// `node.textContent`: every descendant text node concatenated.
pub(crate) fn text_content(node: Node) -> String {
    node.descendants().filter(|n| n.is_text()).filter_map(|n| n.text()).collect()
}

/// Trimmed text of the first `tag` descendant, or `""` when there is none.
pub(crate) fn get_text_content(el: Node, tag: &str) -> String {
    elements_by_tag_name(el, tag)
        .next()
        .map(|n| js_trim(&text_content(n)).to_string())
        .unwrap_or_default()
}

/// First non-empty `get_text_content` among `tags` (the JS `a || b || ''` chain).
fn first_text(el: Node, tags: &[&str]) -> String {
    tags.iter()
        .map(|tag| get_text_content(el, tag))
        .find(|text| !text.is_empty())
        .unwrap_or_default()
}

fn get_attribute(el: Node, attr: &str) -> String {
    el.attribute(attr).unwrap_or_default().to_string()
}

// ── Description clean-up ─────────────────────────────────────────────────

/// Byte offset of the first ASCII-case-insensitive occurrence of `needle`
/// (which must be ASCII) at or after `from`.
fn find_ascii_ci(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (from..=h.len() - n.len()).find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

/// `s.replace(/needle/gi, '')` for a literal ASCII needle.
pub(crate) fn remove_ascii_ci(s: &str, needle: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(i) = find_ascii_ci(s, needle, pos) {
        out.push_str(&s[pos..i]);
        pos = i + needle.len();
    }
    out.push_str(&s[pos..]);
    out
}

/// `s.replace(/<Tag>[\s\S]*?<\/Tag>/gi, '')`: drop each element with its
/// content (non-greedy; an unclosed opening tag is left alone).
fn remove_element_ci(s: &str, tag: &str) -> String {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(start) = find_ascii_ci(s, &open, pos) {
        let Some(end) = find_ascii_ci(s, &close, start + open.len()) else { break };
        out.push_str(&s[pos..start]);
        pos = end + close.len();
    }
    out.push_str(&s[pos..]);
    out
}

/// `.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()`: turn any leftover
/// markup into spaces and collapse whitespace.
pub(crate) fn strip_tags_and_collapse(s: &str) -> String {
    let mut untagged = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(lt) = rest.find('<') {
        untagged.push_str(&rest[..lt]);
        match rest[lt + 1..].find('>') {
            // `<>` is not a tag (`[^>]+` needs at least one character).
            Some(0) => {
                untagged.push('<');
                rest = &rest[lt + 1..];
            }
            Some(gt) => {
                untagged.push(' ');
                rest = &rest[lt + 1 + gt + 1..];
            }
            None => {
                untagged.push_str(&rest[lt..]);
                rest = "";
            }
        }
    }
    untagged.push_str(rest);

    let mut collapsed = String::with_capacity(untagged.len());
    let mut in_whitespace = false;
    for c in untagged.chars() {
        if is_js_whitespace(c) {
            if !in_whitespace {
                collapsed.push(' ');
            }
            in_whitespace = true;
        } else {
            collapsed.push(c);
            in_whitespace = false;
        }
    }
    js_trim(&collapsed).to_string()
}

/// DISA packs several pseudo-elements into the escaped rule description;
/// keep only the VulnDiscussion text.
fn clean_description(desc: &str) -> String {
    const DROPPED: [&str; 10] = [
        "FalsePositives",
        "FalseNegatives",
        "Documentable",
        "Mitigations",
        "SeverityOverrideGuidance",
        "PotentialImpacts",
        "ThirdPartyTools",
        "MitigationControl",
        "Responsibility",
        "IAControls",
    ];
    let mut out = remove_ascii_ci(desc, "<VulnDiscussion>");
    out = remove_ascii_ci(&out, "</VulnDiscussion>");
    for tag in DROPPED {
        out = remove_element_ci(&out, tag);
    }
    strip_tags_and_collapse(&out)
}

// ── Parser ───────────────────────────────────────────────────────────────

const NO_BENCHMARK: &str = "No Benchmark element found in XCCDF";

pub fn parse_xccdf(xml: &str) -> Result<Stig, String> {
    let doc = parse_document(xml).ok_or(NO_BENCHMARK)?;
    let root = doc.root();

    let benchmark = elements_by_tag_name(root, "Benchmark")
        .next()
        .or_else(|| elements_by_local_name(root, "Benchmark").next())
        .ok_or(NO_BENCHMARK)?;

    let title = first_text(benchmark, &["title", "Title"]);
    let title = if title.is_empty() { "Unknown STIG".to_string() } else { title };
    let title = title.strip_prefix("DPMS Target ").unwrap_or(&title).to_string();
    let description = first_text(benchmark, &["description", "Description"]);
    let version = first_text(benchmark, &["version", "Version"]);
    let release_info = first_text(benchmark, &["plain-text", "release-info"]);

    let mut groups: Vec<Node> = elements_by_tag_name(benchmark, "Group").collect();
    if groups.is_empty() {
        groups = elements_by_local_name(benchmark, "Group").collect();
    }

    let mut rules = Vec::new();
    for (i, group) in groups.into_iter().enumerate() {
        let group_id = get_attribute(group, "id");
        let Some(rule_el) = elements_by_tag_name(group, "Rule")
            .next()
            .or_else(|| elements_by_local_name(group, "Rule").next())
        else {
            continue;
        };

        let rule_id = get_attribute(rule_el, "id");
        let severity = get_attribute(rule_el, "severity");
        let severity = if severity.is_empty() { "medium" } else { severity.as_str() };
        let rule_title = first_text(rule_el, &["title", "Title"]);
        let rule_desc = first_text(rule_el, &["description", "Description"]);
        let fix_text = first_text(rule_el, &["fixtext", "fix", "Fix"]);
        let check_text = get_text_content(rule_el, "check-content");

        let cci_ids = elements_by_tag_name(rule_el, "ident")
            .map(|ident| js_trim(&text_content(ident)).to_string())
            .filter(|val| !val.is_empty())
            .collect();

        let stig_id = if group_id.is_empty() { format!("V-{}", 100_000 + i) } else { group_id.clone() };

        rules.push(Rule {
            id: if rule_id.is_empty() { format!("rule-{i}") } else { rule_id },
            stig_id,
            group_id,
            title: rule_title,
            severity: severity_label(severity).unwrap_or("CAT II").to_string(),
            description: clean_description(&rule_desc),
            fix_text,
            check_text,
            cci_ids,
            status: "not_reviewed".to_string(),
            finding_details: String::new(),
            comments: String::new(),
            extra: Default::default(),
        });
    }

    Ok(Stig { title, description, version, release_info, rules })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shared fixture — any drift here must be mirrored in the backend parity
    // test in backend/src/parser/mod.rs.
    const XML: &str = include_str!("../../../testdata/fixtures/minimal.xccdf.xml");

    fn by_stig_id<'a>(stig: &'a Stig, stig_id: &str) -> &'a Rule {
        stig.rules.iter().find(|r| r.stig_id == stig_id).expect("rule present")
    }

    #[test]
    fn extracts_the_stig_level_title_and_version() {
        let stig = parse_xccdf(XML).unwrap();
        assert_eq!(stig.title, "Parity Fixture STIG");
        assert_eq!(stig.version, "2");
        assert_eq!(stig.description, "Shared fixture for FE/BE parser parity tests.");
        assert_eq!(stig.release_info, "Release: 4 Benchmark Date: 01 Jan 2026");
    }

    #[test]
    fn parses_exactly_three_rules_with_the_expected_ids_and_severities() {
        let stig = parse_xccdf(XML).unwrap();
        assert_eq!(stig.rules.len(), 3);

        assert_eq!(by_stig_id(&stig, "V-1001").severity, "CAT I");
        assert_eq!(by_stig_id(&stig, "V-1001").id, "SV-1001r1_rule");
        assert_eq!(by_stig_id(&stig, "V-1001").title, "Critical rule under test");

        assert_eq!(by_stig_id(&stig, "V-1002").severity, "CAT II");
        assert_eq!(by_stig_id(&stig, "V-1002").id, "SV-1002r1_rule");

        assert_eq!(by_stig_id(&stig, "V-1003").severity, "CAT III");
        assert_eq!(by_stig_id(&stig, "V-1003").id, "SV-1003r1_rule");
    }

    #[test]
    fn strips_vuln_discussion_and_false_positives_from_descriptions() {
        let stig = parse_xccdf(XML).unwrap();
        let critical = stig.rules.iter().find(|r| r.id == "SV-1001r1_rule").unwrap();
        assert_eq!(critical.description, "Why this critical finding matters.");
        assert!(!critical.description.contains("FalsePositives"));
        assert!(!critical.description.contains('<'));
    }

    #[test]
    fn collects_cci_references_per_rule() {
        let stig = parse_xccdf(XML).unwrap();
        let critical = stig.rules.iter().find(|r| r.id == "SV-1001r1_rule").unwrap();
        assert_eq!(critical.cci_ids, vec!["CCI-000015", "CCI-000017"]);
        assert!(by_stig_id(&stig, "V-1003").cci_ids.is_empty());
    }

    #[test]
    fn initialises_every_rule_to_not_reviewed_with_empty_override_fields() {
        let stig = parse_xccdf(XML).unwrap();
        for r in &stig.rules {
            assert_eq!(r.status, "not_reviewed");
            assert_eq!(r.finding_details, "");
            assert_eq!(r.comments, "");
        }
    }

    #[test]
    fn reads_fix_and_check_text() {
        let stig = parse_xccdf(XML).unwrap();
        let critical = by_stig_id(&stig, "V-1001");
        assert_eq!(critical.fix_text, "Apply the configuration change.");
        assert_eq!(critical.check_text, "Verify the setting with a runtime probe.");
        assert_eq!(critical.group_id, "V-1001");
    }

    #[test]
    fn missing_benchmark_and_malformed_xml_are_errors() {
        assert_eq!(parse_xccdf("<CHECKLIST/>").unwrap_err(), NO_BENCHMARK);
        assert_eq!(parse_xccdf("<Benchmark><title>").unwrap_err(), NO_BENCHMARK);
        assert_eq!(parse_xccdf("").unwrap_err(), NO_BENCHMARK);
    }

    #[test]
    fn applies_defaults_and_fallback_ids() {
        let stig = parse_xccdf(
            r#"<Benchmark>
                 <title>  DPMS Target Widget OS </title>
                 <Group><title>no rule here</title></Group>
                 <Group><Rule><Title>Cap title</Title><fix>do it</fix></Rule></Group>
                 <Group id="V-9"><Rule id="r9" severity="critical"><ident> </ident><ident> CCI-1 </ident></Rule></Group>
               </Benchmark>"#,
        )
        .unwrap();
        assert_eq!(stig.title, "Widget OS");
        assert_eq!(stig.description, "");
        assert_eq!(stig.rules.len(), 2);

        // Indices count every Group, including the one skipped for having no Rule.
        let first = &stig.rules[0];
        assert_eq!(first.id, "rule-1");
        assert_eq!(first.stig_id, "V-100001");
        assert_eq!(first.group_id, "");
        assert_eq!(first.title, "Cap title");
        assert_eq!(first.fix_text, "do it");
        assert_eq!(first.severity, "CAT II");
        assert_eq!(first.check_text, "");

        let second = &stig.rules[1];
        assert_eq!(second.id, "r9");
        assert_eq!(second.stig_id, "V-9");
        assert_eq!(second.severity, "CAT II"); // unknown severity
        assert_eq!(second.cci_ids, vec!["CCI-1"]);
    }

    #[test]
    fn untitled_benchmark_is_unknown_stig() {
        assert_eq!(parse_xccdf("<Benchmark/>").unwrap().title, "Unknown STIG");
        // The Benchmark's own title wins only if it comes first in document
        // order: getElementsByTagName is a deep search.
        let nested = parse_xccdf(
            "<Benchmark><Group id=\"g\"><title>Group title</title></Group><title>Late</title></Benchmark>",
        )
        .unwrap();
        assert_eq!(nested.title, "Group title");
    }

    #[test]
    fn prefixed_documents_fall_back_to_local_names_for_structure_only() {
        let stig = parse_xccdf(
            r#"<cdf:Benchmark xmlns:cdf="http://checklists.nist.gov/xccdf/1.1" xmlns:dc="http://purl.org/dc/elements/1.1/">
                 <cdf:title>Prefixed</cdf:title>
                 <cdf:Group id="V-1"><cdf:Rule id="r1" severity="high"><cdf:title>t</cdf:title></cdf:Rule></cdf:Group>
               </cdf:Benchmark>"#,
        )
        .unwrap();
        // Benchmark / Group / Rule use the any-namespace fallback; text lookups
        // (`title`, ...) match qualified names only, exactly like the DOM.
        assert_eq!(stig.title, "Unknown STIG");
        assert_eq!(stig.rules.len(), 1);
        assert_eq!(stig.rules[0].id, "r1");
        assert_eq!(stig.rules[0].severity, "CAT I");
        assert_eq!(stig.rules[0].title, "");
    }

    #[test]
    fn qualified_name_lookup_skips_foreign_prefixed_elements() {
        let stig = parse_xccdf(
            r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" xmlns:dc="http://purl.org/dc/elements/1.1/">
                 <reference><dc:title>DC title</dc:title></reference>
                 <title>Real title</title>
               </Benchmark>"#,
        )
        .unwrap();
        assert_eq!(stig.title, "Real title");
    }

    #[test]
    fn text_content_concatenates_nested_text_and_cdata() {
        let stig = parse_xccdf(
            "<Benchmark><title>A <b>bold</b><![CDATA[ & <raw>]]> title<!-- no --></title></Benchmark>",
        )
        .unwrap();
        assert_eq!(stig.title, "A bold & <raw> title");
    }

    #[test]
    fn clean_description_matches_the_js_regex_chain() {
        assert_eq!(
            clean_description(
                "<vulndiscussion>Keep\n  this.</VULNDISCUSSION><falsepositives>x\ny</FalsePositives>\
                 <Documentable>false</Documentable><IAControls></IAControls><b>bold</b> end"
            ),
            "Keep this. bold end"
        );
        // Unclosed pseudo-elements are not swallowed; the bare tag becomes a space.
        assert_eq!(clean_description("a<Mitigations>b"), "a b");
        // Non-greedy: only up to the first closing tag.
        assert_eq!(
            clean_description("<Mitigations>1</Mitigations>mid<Mitigations>2</Mitigations>"),
            "mid"
        );
        assert_eq!(clean_description("a <> b < c"), "a <> b < c");
        assert_eq!(clean_description("x<>y>z"), "x<>y>z");
        assert_eq!(clean_description("\u{FEFF} a\u{A0}\u{2003}b \t"), "a b");
    }

    #[test]
    fn js_trim_uses_the_ecmascript_whitespace_set() {
        assert_eq!(js_trim("\u{FEFF}\t a b \u{2028}\u{3000}"), "a b");
        assert_eq!(js_trim("\u{85}a\u{85}"), "\u{85}a\u{85}");
    }
}
