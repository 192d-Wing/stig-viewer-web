//! Exclusive XML canonicalisation (RFC 3741, `xml-exc-c14n#`) of a parsed
//! [`SamlDoc`] subtree, with optional enveloped-signature omission.
//!
//! The canonical bytes are serialised from the parsed nodes, not sliced from
//! the wire, so what is digested is exactly what `saml::extract` reads.
//!
//! Scope: elements, attributes, namespace declarations, text and CDATA. The
//! parser rejects comments, processing instructions and DOCTYPE, so the
//! `#WithComments` variant canonicalises identically to the plain one.
//!
//! Known exclusive-c14n limit: a prefix that is used only inside attribute
//! values or text (for example `xsi:type="xs:string"`) is signed only if it
//! is listed in an `InclusiveNamespaces` `PrefixList`. Callers must never
//! interpret QName content.

use anyhow::{anyhow, bail, Result};
use std::collections::BTreeMap;

use crate::api::saml_xml::{Content, SamlDoc, MAX_DOC_BYTES};

pub const NS_EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Cap on canonical output. A long namespace URI declared on the root is
/// re-rendered on every sibling subtree that uses it, so the output can be
/// far larger than the input.
pub const MAX_C14N_BYTES: usize = 4 * MAX_DOC_BYTES;

struct Ctx<'a> {
    doc: &'a SamlDoc,
    omit: Option<usize>,
    inclusive: &'a [String],
    out: Vec<u8>,
}

/// An attribute as (namespace uri, local name, qname as written, value).
type Attr<'a> = (&'a str, &'a str, &'a str, &'a str);

impl<'a> Ctx<'a> {
    fn put(&mut self, s: &str) -> Result<()> {
        self.out.extend_from_slice(s.as_bytes());
        if self.out.len() > MAX_C14N_BYTES {
            bail!("canonical form too large");
        }
        Ok(())
    }

    /// Candidate namespace prefixes for element `i` (true when visibly
    /// utilised, false when only on the InclusiveNamespaces PrefixList), and
    /// its attributes as (ns uri, local, qname, value).
    fn candidates_and_attrs(&self, i: usize) -> Result<(BTreeMap<String, bool>, Vec<Attr<'a>>)> {
        let doc = self.doc;
        let n = doc.node(i);
        let mut cand: BTreeMap<String, bool> = BTreeMap::new();
        for p in self.inclusive {
            let p = if p == "#default" { "" } else { p.as_str() };
            cand.entry(p.to_string()).or_insert(false);
        }
        cand.insert(n.prefix.clone(), true);
        let mut attrs = Vec::with_capacity(n.attrs.len());
        for (k, v) in &n.attrs {
            let (uri, local) = match k.split_once(':') {
                Some((p, l)) => {
                    if p != "xml" {
                        cand.insert(p.to_string(), true);
                    }
                    let uri = doc
                        .ns_of_prefix(i, p)
                        .ok_or_else(|| anyhow!("unbound attribute prefix"))?;
                    (uri, l)
                }
                None => ("", k.as_str()),
            };
            attrs.push((uri, local, k.as_str(), v.as_str()));
        }
        cand.remove("xml");
        Ok((cand, attrs))
    }

    fn emit(&mut self, i: usize, rendered: &mut Vec<(String, String)>) -> Result<()> {
        if Some(i) == self.omit {
            return Ok(());
        }
        let doc = self.doc;
        let n = doc.node(i);
        let mark = rendered.len();
        let (cand, mut attrs) = self.candidates_and_attrs(i)?;

        // BTreeMap order puts the default namespace ("") first, then prefixes sorted.
        let mut decls: Vec<(String, Option<String>)> = Vec::new();
        for (p, visible) in &cand {
            let latest = rendered
                .iter()
                .rev()
                .find(|(rp, _)| rp == p)
                .map(|(_, u)| u);
            match doc.ns_of_prefix(i, p) {
                Some(u) => {
                    if latest.is_none_or(|ru| ru != u) {
                        decls.push((p.clone(), Some(u.to_string())));
                    }
                }
                None if p.is_empty() => {
                    if latest.is_some_and(|ru| !ru.is_empty()) {
                        decls.push((String::new(), None));
                    }
                }
                None if *visible => bail!("unbound namespace prefix"),
                None => {}
            }
        }
        for (p, u) in &decls {
            rendered.push((p.clone(), u.clone().unwrap_or_default()));
        }

        let qname = if n.prefix.is_empty() {
            n.local.clone()
        } else {
            format!("{}:{}", n.prefix, n.local)
        };
        self.put(&format!("<{qname}"))?;
        for (p, u) in &decls {
            let u = u.as_deref().unwrap_or("");
            if p.is_empty() {
                self.put(&format!(" xmlns=\"{}\"", esc_attr(u)))?;
            } else {
                self.put(&format!(" xmlns:{p}=\"{}\"", esc_attr(u)))?;
            }
        }
        attrs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        for (_, _, k, v) in &attrs {
            self.put(&format!(" {k}=\"{}\"", esc_attr(v)))?;
        }
        self.put(">")?;
        for c in &n.content {
            match c {
                Content::Text(t) => self.put(&esc_text(t))?,
                Content::Child(ch) => self.emit(*ch, rendered)?,
            }
        }
        self.put(&format!("</{qname}>"))?;
        rendered.truncate(mark);
        Ok(())
    }
}

fn esc_text(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '\r' => o.push_str("&#xD;"),
            c => o.push(c),
        }
    }
    o
}

fn esc_attr(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '"' => o.push_str("&quot;"),
            '\t' => o.push_str("&#x9;"),
            '\n' => o.push_str("&#xA;"),
            '\r' => o.push_str("&#xD;"),
            c => o.push(c),
        }
    }
    o
}

/// Exclusive canonical form of the subtree rooted at `apex`.
///
/// `omit` is a node (inside the subtree) that is emitted as nothing, for the
/// enveloped-signature transform. `inclusive_prefixes` is the
/// `InclusiveNamespaces` `PrefixList` (`#default` names the default namespace).
pub fn canonicalize(
    doc: &SamlDoc,
    apex: usize,
    omit: Option<usize>,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>> {
    let mut c = Ctx {
        doc,
        omit,
        inclusive: inclusive_prefixes,
        out: Vec::new(),
    };
    c.emit(apex, &mut Vec::new())?;
    Ok(c.out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(xml: &str, apex: usize, omit: Option<usize>, pl: &[&str]) -> String {
        let doc = SamlDoc::parse_tree(xml).unwrap();
        let pl: Vec<String> = pl.iter().map(|s| s.to_string()).collect();
        String::from_utf8(canonicalize(&doc, apex, omit, &pl).unwrap()).unwrap()
    }

    fn whole(xml: &str) -> String {
        canon(xml, 0, None, &[])
    }

    // Expected values below were produced with `xmllint --exc-c14n` (libxml2
    // 2.9.13) on the same inputs; the two hand edits are noted inline.
    #[test]
    fn v1_unused_namespaces_are_dropped() {
        assert_eq!(
            whole(
                r#"<n0:local xmlns:n0="foo:bar" xmlns:n3="ftp://example.org" xmlns:unused="urn:u"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"/></n1:elem2></n0:local>"#
            ),
            r#"<n0:local xmlns:n0="foo:bar"><n1:elem2 xmlns:n1="http://example.net" xml:lang="en"><n3:stuff xmlns:n3="ftp://example.org"></n3:stuff></n1:elem2></n0:local>"#
        );
    }

    #[test]
    fn v2_attribute_order_quoting_escaping_and_text() {
        let xml = "<a:doc  xmlns:b=\"urn:b\"   xmlns:a=\"urn:a\" b:z=\"1\"  a:y=\"2\" x=\"3\"   c='&quot;q&apos; &lt; &gt; &amp; &#9;&#10;&#13;' d=\"l1\nl2\tt\"><a:e/><a:t>x &gt; y &amp; z &#13; <![CDATA[<c&d>]]>]</a:t><d xmlns=\"urn:d\"><q:f xmlns:q=\"urn:d\" q:a=\"1\" xmlns:a=\"urn:a\" a:a=\"0\"/></d>\n  <a:ws> </a:ws>\n</a:doc>";
        let want = "<a:doc xmlns:a=\"urn:a\" xmlns:b=\"urn:b\" c=\"&quot;q' &lt; > &amp; &#x9;&#xA;&#xD;\" d=\"l1 l2 t\" x=\"3\" a:y=\"2\" b:z=\"1\"><a:e></a:e><a:t>x &gt; y &amp; z &#xD; &lt;c&amp;d&gt;]</a:t><d xmlns=\"urn:d\"><q:f xmlns:q=\"urn:d\" a:a=\"0\" q:a=\"1\"></q:f></d>\n  <a:ws> </a:ws>\n</a:doc>";
        assert_eq!(whole(xml), want);
    }

    #[test]
    fn v3_line_endings_are_normalised() {
        assert_eq!(
            whole("<a:r xmlns:a=\"urn:a\">l1\r\nl2\rl3</a:r>"),
            "<a:r xmlns:a=\"urn:a\">l1\nl2\nl3</a:r>"
        );
    }

    #[test]
    fn subtree_apex_renders_inherited_declarations() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:p" xmlns:saml="urn:s" xmlns:unused="urn:u"><saml:Assertion ID="AS1"><saml:X/></saml:Assertion></samlp:Response>"#;
        assert_eq!(
            canon(xml, 1, None, &[]),
            r#"<saml:Assertion xmlns:saml="urn:s" ID="AS1"><saml:X></saml:X></saml:Assertion>"#
        );
    }

    #[test]
    fn redeclarations_are_rendered_only_when_they_change_the_binding() {
        assert_eq!(
            whole(r#"<a:r xmlns:a="urn:a"><a:c xmlns:a="urn:a"/></a:r>"#),
            r#"<a:r xmlns:a="urn:a"><a:c></a:c></a:r>"#
        );
        assert_eq!(
            whole(r#"<a:r xmlns:a="urn:a"><a:c xmlns:a="urn:b"/><a:d/></a:r>"#),
            r#"<a:r xmlns:a="urn:a"><a:c xmlns:a="urn:b"></a:c><a:d></a:d></a:r>"#
        );
    }

    #[test]
    fn inclusive_prefix_list() {
        let xml =
            r#"<saml:r xmlns:xs="urn:xs" xmlns:saml="urn:s" xmlns="urn:d"><saml:c/></saml:r>"#;
        assert_eq!(
            canon(xml, 0, None, &["xs"]),
            r#"<saml:r xmlns:saml="urn:s" xmlns:xs="urn:xs"><saml:c></saml:c></saml:r>"#
        );
        assert_eq!(
            canon(xml, 0, None, &["#default", "xs"]),
            r#"<saml:r xmlns="urn:d" xmlns:saml="urn:s" xmlns:xs="urn:xs"><saml:c></saml:c></saml:r>"#
        );
        // A listed prefix that is not in scope is ignored.
        assert_eq!(
            canon(xml, 0, None, &["nope"]),
            r#"<saml:r xmlns:saml="urn:s"><saml:c></saml:c></saml:r>"#
        );
        // Undeclaring the default namespace below a rendered default.
        let xml = r#"<a:r xmlns:a="urn:a" xmlns="urn:d"><a:c xmlns=""/></a:r>"#;
        assert_eq!(
            canon(xml, 0, None, &["#default"]),
            r#"<a:r xmlns="urn:d" xmlns:a="urn:a"><a:c xmlns=""></a:c></a:r>"#
        );
    }

    #[test]
    fn omit_removes_only_the_given_child() {
        let xml = "<a:r xmlns:a=\"urn:a\">\n <a:s/>\n <a:t/>\n</a:r>";
        assert_eq!(
            canon(xml, 0, Some(1), &[]),
            "<a:r xmlns:a=\"urn:a\">\n \n <a:t></a:t>\n</a:r>"
        );
    }

    #[test]
    fn output_is_size_capped() {
        // `a` is declared on a root that does not use it, so every sibling
        // that does use it renders the long URI again.
        let big = "u".repeat(100 * 1024);
        let xml = format!(
            r#"<r:root xmlns:r="urn:r" xmlns:a="{big}">{}</r:root>"#,
            "<a:s/>".repeat(12)
        );
        let doc = SamlDoc::parse_tree(&xml).unwrap();
        let e = canonicalize(&doc, 0, None, &[]).unwrap_err();
        assert!(e.to_string().contains("canonical form too large"), "{e}");
    }

    #[test]
    fn references_and_cdata_canonicalise_byte_exact() {
        assert_eq!(
            whole("<a xmlns=\"urn:a\">x &amp; y&#13;\r\n&gt;<![CDATA[&amp;]]>&quot;&apos;</a>"),
            "<a xmlns=\"urn:a\">x &amp; y&#xD;\n&gt;&amp;amp;\"'</a>"
        );
    }
}
