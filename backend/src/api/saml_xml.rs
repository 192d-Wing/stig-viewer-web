//! Strict, single-pass XML front end for SAMLResponse documents.
//!
//! The document is parsed exactly once with `quick-xml` into an index of
//! elements (namespace, local name, declarations, attributes, ordered
//! content, parent, byte span). Signature verification (`saml_verify`,
//! which canonicalises this tree via `saml_c14n`) and identity extraction
//! (`saml`) work from this one tree, so the bytes that are digested are
//! serialised from the same nodes the identity is read from.
//!
//! quick-xml 0.37 performs neither attribute-value normalisation nor
//! end-of-line normalisation, so this module does both (XML 1.0 3.3.3 and
//! 2.11) and checks every character against the XML 1.0 `Char` range.
//!
//! The parser fails closed: DOCTYPE, processing instructions (other than
//! the XML declaration), comments, duplicate attributes, unknown namespace
//! prefixes, duplicate `ID` values, EncryptedAssertion, and anything other
//! than exactly one `Assertion` that is a direct child of the root
//! `samlp:Response` are all rejected.

use anyhow::{anyhow, bail, Result};
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;
use std::collections::HashSet;

pub const NS_PROTO: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_ASSERT: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Largest SAMLResponse document accepted.
pub const MAX_DOC_BYTES: usize = 256 * 1024;
/// Structural caps (DoS bounds).
pub const MAX_ELEMENTS: usize = 2000;
pub const MAX_DEPTH: usize = 32;
pub const MAX_ATTRS: usize = 32;

/// A rejection carrying a fixed audit reason code, so classification never
/// depends on rendered (attacker-influenced) text.
#[derive(Debug)]
pub struct Reject {
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for Reject {}

/// Build an error with a fixed reason code.
pub fn reject(code: &'static str, detail: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Reject {
        code,
        detail: detail.into(),
    })
}

/// Give `e` the stage default `code` unless it already carries one.
pub fn tag(code: &'static str, e: anyhow::Error) -> anyhow::Error {
    if e.chain().any(|c| c.is::<Reject>()) {
        e
    } else {
        reject(code, format!("{e:#}"))
    }
}

/// The fixed reason code of `e` (`invalid_response` if untagged).
pub fn code_of(e: &anyhow::Error) -> &'static str {
    e.chain()
        .find_map(|c| c.downcast_ref::<Reject>())
        .map(|r| r.code)
        .unwrap_or("invalid_response")
}

/// Namespace bound to the reserved `xml` prefix.
pub const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";

/// One piece of an element's content, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Character data (text and CDATA merged), line endings normalised.
    Text(String),
    /// A child element, by node index.
    Child(usize),
}

#[derive(Debug)]
pub struct Node {
    pub ns: String,
    pub local: String,
    /// Element prefix as written ("" for unprefixed).
    pub prefix: String,
    /// Namespace declarations on this element as (prefix, uri); "" is the
    /// default namespace.
    pub decls: Vec<(String, String)>,
    /// Non-`xmlns` attributes as (qualified name as written, normalised value).
    pub attrs: Vec<(String, String)>,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Byte offsets into the source: `start` at `<`, `end` just past the final `>`.
    pub start: usize,
    pub end: usize,
    /// Concatenated direct text and CDATA.
    pub text: String,
    /// Direct text and children interleaved in document order.
    pub content: Vec<Content>,
}

#[derive(Debug)]
pub struct SamlDoc {
    nodes: Vec<Node>,
}

/// XML 1.0 `Char` production.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

fn check_chars(s: &str) -> Result<()> {
    if s.chars().all(is_xml_char) {
        Ok(())
    } else {
        bail!("character outside the XML 1.0 Char range")
    }
}

/// XML 1.0 2.11 end-of-line handling: `\r\n` and lone `\r` become `\n`.
fn normalize_eol(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// XML 1.0 3.3.3 attribute-value normalisation for CDATA attributes, applied
/// to the literal text before entity expansion: each of `\r\n`, `\r`, `\n`
/// and `\t` becomes one space.
fn normalize_attr(s: &str) -> String {
    s.replace("\r\n", " ").replace(['\r', '\n', '\t'], " ")
}

fn unescape_checked(s: &str) -> Result<String> {
    let v = quick_xml::escape::unescape(s)
        .map_err(|e| anyhow!("bad entity: {e}"))?
        .into_owned();
    check_chars(&v)?;
    Ok(v)
}

/// XML `NCName` (name without a colon).
fn is_ncname(s: &str) -> bool {
    let mut it = s.chars();
    it.next().is_some_and(|c| c == '_' || c.is_alphabetic())
        && it.all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// `NCName` or `NCName:NCName`; returns (prefix, local).
fn split_qname(name: &str) -> Result<(&str, &str)> {
    let (p, l) = name.split_once(':').unwrap_or(("", name));
    if (!p.is_empty() || name.contains(':')) && !is_ncname(p) || !is_ncname(l) {
        bail!("name is not a namespace-well-formed QName");
    }
    Ok((p, l))
}

/// Build a node from a start/empty tag (without linking it into the tree).
fn make_node(
    ns: String,
    e: &quick_xml::events::BytesStart<'_>,
    parent: Option<usize>,
    start: usize,
    end: usize,
) -> Result<Node> {
    if ns.is_empty() {
        bail!("element without a namespace");
    }
    let name = std::str::from_utf8(e.name().as_ref())
        .map_err(|_| anyhow!("element name not utf-8"))?
        .to_string();
    let (prefix, local) = {
        let (p, l) = split_qname(&name)?;
        (p.to_string(), l.to_string())
    };
    let (mut attrs, mut decls) = (Vec::new(), Vec::new());
    let mut seen = 0usize;
    for a in e.attributes() {
        seen += 1;
        if seen > MAX_ATTRS {
            bail!("too many attributes");
        }
        let a = a.map_err(|e| anyhow!("bad attribute: {e}"))?;
        let key = std::str::from_utf8(a.key.as_ref())
            .map_err(|_| anyhow!("attribute name not utf-8"))?
            .to_string();
        let raw =
            std::str::from_utf8(&a.value).map_err(|_| anyhow!("attribute value not utf-8"))?;
        if raw.contains('<') {
            bail!("'<' in attribute value");
        }
        let val = unescape_checked(&normalize_attr(raw))?;
        if key == "xmlns" || key.starts_with("xmlns:") {
            // No entities, whitespace or control characters: the raw text then
            // equals the normalised value, so `Node.ns` and `ns_of_prefix` agree.
            if raw.contains('&') || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
                bail!("namespace declaration value not accepted");
            }
            let p = key.strip_prefix("xmlns:").unwrap_or("");
            if key != "xmlns" && !is_ncname(p) {
                bail!("namespace declaration prefix not accepted");
            }
            if p == "xml" || p == "xmlns" || (!key.eq("xmlns") && val.is_empty()) {
                bail!("namespace declaration not accepted");
            }
            decls.push((p.to_string(), val));
        } else {
            split_qname(&key)?;
            attrs.push((key, val));
        }
    }
    Ok(Node {
        ns,
        local,
        prefix,
        decls,
        attrs,
        parent,
        children: Vec::new(),
        start,
        end,
        text: String::new(),
        content: Vec::new(),
    })
}

/// Append character data to element `idx`, keeping `text` and `content` in step.
fn push_text(nodes: &mut [Node], idx: usize, s: &str) {
    if s.is_empty() {
        return;
    }
    nodes[idx].text.push_str(s);
    if let Some(Content::Text(t)) = nodes[idx].content.last_mut() {
        t.push_str(s);
    } else {
        nodes[idx].content.push(Content::Text(s.to_string()));
    }
}

/// Append `n`, link it to its parent, enforce the element cap and the
/// "identity elements only inside an Assertion" rule.
fn add_node(nodes: &mut Vec<Node>, n: Node, in_assertion: bool) -> Result<usize> {
    if nodes.len() >= MAX_ELEMENTS {
        bail!("too many elements");
    }
    if n.ns == NS_ASSERT
        && !in_assertion
        && matches!(
            n.local.as_str(),
            "Subject"
                | "NameID"
                | "EncryptedID"
                | "AttributeStatement"
                | "Attribute"
                | "AttributeValue"
        )
    {
        bail!("identity element {} outside Assertion", n.local);
    }
    let idx = nodes.len();
    if let Some(p) = n.parent {
        nodes[p].children.push(idx);
        nodes[p].content.push(Content::Child(idx));
    }
    nodes.push(n);
    Ok(idx)
}

impl SamlDoc {
    pub fn parse(xml: &str) -> Result<SamlDoc> {
        let doc = Self::build(xml)?;
        doc.validate()?;
        Ok(doc)
    }

    /// Parse without the SAML-shape rules (attribute checks still apply), so
    /// canonicalisation can be tested on arbitrary documents.
    #[cfg(test)]
    pub(crate) fn parse_tree(xml: &str) -> Result<SamlDoc> {
        let doc = Self::build(xml)?;
        doc.validate_attrs()?;
        Ok(doc)
    }

    fn build(xml: &str) -> Result<SamlDoc> {
        if xml.len() > MAX_DOC_BYTES {
            bail!("SAMLResponse exceeds {MAX_DOC_BYTES} bytes");
        }
        let mut r = NsReader::from_str(xml);
        let mut nodes: Vec<Node> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        let mut root_done = false;
        let mut in_assertion = 0usize;

        loop {
            let before = r.buffer_position() as usize;
            let (res, ev) = r
                .read_resolved_event()
                .map_err(|e| anyhow!("xml parse error at {before}: {e}"))?;
            let ns = match res {
                ResolveResult::Bound(n) => std::str::from_utf8(n.as_ref())
                    .map_err(|_| anyhow!("namespace not utf-8"))?
                    .to_string(),
                ResolveResult::Unbound => String::new(),
                ResolveResult::Unknown(_) => bail!("unknown namespace prefix"),
            };
            let after = r.buffer_position() as usize;
            match ev {
                Event::Start(e) => {
                    if stack.is_empty() {
                        if root_done {
                            bail!("more than one root element");
                        }
                        root_done = true;
                    }
                    if stack.len() >= MAX_DEPTH {
                        bail!("element nesting too deep");
                    }
                    let n = make_node(ns, &e, stack.last().copied(), before, after)?;
                    let is_assertion = n.ns == NS_ASSERT && n.local == "Assertion";
                    let idx = add_node(&mut nodes, n, in_assertion > 0)?;
                    if is_assertion {
                        in_assertion += 1;
                    }
                    stack.push(idx);
                }
                Event::Empty(e) => {
                    if stack.is_empty() {
                        if root_done {
                            bail!("more than one root element");
                        }
                        root_done = true;
                    }
                    if stack.len() >= MAX_DEPTH {
                        bail!("element nesting too deep");
                    }
                    let n = make_node(ns, &e, stack.last().copied(), before, after)?;
                    add_node(&mut nodes, n, in_assertion > 0)?;
                }
                Event::End(_) => {
                    let idx = stack.pop().ok_or_else(|| anyhow!("unbalanced end tag"))?;
                    nodes[idx].end = after;
                    if nodes[idx].ns == NS_ASSERT && nodes[idx].local == "Assertion" {
                        in_assertion -= 1;
                    }
                }
                Event::Text(t) => {
                    let raw = std::str::from_utf8(&t).map_err(|_| anyhow!("text not utf-8"))?;
                    let s = unescape_checked(&normalize_eol(raw))?;
                    match stack.last() {
                        Some(&i) => push_text(&mut nodes, i, &s),
                        None if s.trim().is_empty() => {}
                        None => bail!("text outside root element"),
                    }
                }
                Event::CData(c) => {
                    let raw = std::str::from_utf8(&c).map_err(|_| anyhow!("CDATA not utf-8"))?;
                    let s = normalize_eol(raw);
                    check_chars(&s)?;
                    match stack.last() {
                        Some(&i) => push_text(&mut nodes, i, &s),
                        None => bail!("CDATA outside root element"),
                    }
                }
                Event::Decl(_) if nodes.is_empty() => {}
                Event::Decl(_) => bail!("XML declaration after root"),
                Event::Comment(_) => bail!("XML comments are not accepted"),
                Event::DocType(_) => bail!("DOCTYPE is not accepted"),
                Event::PI(_) => bail!("processing instructions are not accepted"),
                Event::Eof => break,
            }
        }
        if !stack.is_empty() || nodes.is_empty() {
            bail!("incomplete XML document");
        }
        Ok(SamlDoc { nodes })
    }

    /// Every attribute prefix must resolve, and no two attributes of an
    /// element may share an expanded name.
    fn validate_attrs(&self) -> Result<()> {
        for (i, n) in self.nodes.iter().enumerate() {
            let mut expanded = HashSet::new();
            for (k, _) in &n.attrs {
                let (uri, local) = match k.split_once(':') {
                    Some((p, l)) => (
                        self.ns_of_prefix(i, p)
                            .ok_or_else(|| anyhow!("unknown attribute namespace prefix"))?,
                        l,
                    ),
                    None => ("", k.as_str()),
                };
                if !expanded.insert((uri, local)) {
                    bail!("duplicate attribute {{{uri}}}{local}");
                }
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        self.validate_attrs()?;
        let root = &self.nodes[0];
        if root.ns != NS_PROTO || root.local != "Response" {
            bail!("root element is not samlp:Response");
        }
        let mut ids = HashSet::new();
        let mut assertions = 0;
        for (i, n) in self.nodes.iter().enumerate() {
            if let Some(id) = self.attr(i, "ID") {
                if !ids.insert(id) {
                    bail!("duplicate ID {id:?}");
                }
            }
            if n.ns == NS_ASSERT {
                match n.local.as_str() {
                    "EncryptedAssertion" => bail!("EncryptedAssertion is not supported"),
                    "Assertion" => {
                        assertions += 1;
                        if n.parent != Some(0) {
                            bail!("Assertion is not a direct child of Response");
                        }
                    }
                    _ => {}
                }
            }
        }
        if assertions != 1 {
            bail!("expected exactly one Assertion, found {assertions}");
        }
        Ok(())
    }

    pub fn root(&self) -> usize {
        0
    }

    pub fn node(&self, i: usize) -> &Node {
        &self.nodes[i]
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Namespace URI bound to `prefix` ("" is the default namespace) in the
    /// scope of element `i`: the nearest declaration on `i` or an ancestor.
    /// `None` when unbound (including a default namespace undeclared with `xmlns=""`).
    pub fn ns_of_prefix(&self, i: usize, prefix: &str) -> Option<&str> {
        if prefix == "xml" {
            return Some(NS_XML);
        }
        let mut cur = Some(i);
        while let Some(c) = cur {
            if let Some((_, u)) = self.nodes[c].decls.iter().find(|(p, _)| p == prefix) {
                return (!u.is_empty()).then_some(u.as_str());
            }
            cur = self.nodes[c].parent;
        }
        None
    }

    /// Unprefixed attribute value.
    pub fn attr(&self, i: usize, name: &str) -> Option<&str> {
        self.nodes[i]
            .attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn is(&self, i: usize, ns: &str, local: &str) -> bool {
        self.nodes[i].ns == ns && self.nodes[i].local == local
    }

    /// Direct children with the given namespace and local name.
    pub fn children(&self, i: usize, ns: &str, local: &str) -> Vec<usize> {
        self.nodes[i]
            .children
            .iter()
            .copied()
            .filter(|&c| self.is(c, ns, local))
            .collect()
    }

    /// At most one such child; error if duplicated.
    pub fn child_opt(&self, i: usize, ns: &str, local: &str) -> Result<Option<usize>> {
        let c = self.children(i, ns, local);
        match c.len() {
            0 => Ok(None),
            1 => Ok(Some(c[0])),
            _ => bail!("duplicate {local} element"),
        }
    }

    /// Exactly one such child.
    pub fn child_one(&self, i: usize, ns: &str, local: &str) -> Result<usize> {
        self.child_opt(i, ns, local)?
            .ok_or_else(|| anyhow!("missing {local} element"))
    }

    /// Text of a leaf element (no element children), trimmed.
    pub fn leaf_text(&self, i: usize) -> Result<&str> {
        if !self.nodes[i].children.is_empty() {
            bail!("unexpected child elements in {}", self.nodes[i].local);
        }
        Ok(self.nodes[i].text.trim())
    }

    /// All elements strictly inside `i`, in document order.
    pub fn descendants(&self, i: usize) -> Vec<usize> {
        let (s, e) = (self.nodes[i].start, self.nodes[i].end);
        (0..self.nodes.len())
            .filter(|&j| j != i && self.nodes[j].start >= s && self.nodes[j].end <= e)
            .collect()
    }

    /// The single `Assertion` element (guaranteed by `parse`).
    pub fn assertion(&self) -> Result<usize> {
        self.child_one(0, NS_ASSERT, "Assertion")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: &str = r#"xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#;

    fn resp(inner: &str) -> String {
        format!("<?xml version=\"1.0\"?>\n<samlp:Response {R} ID=\"r\">{inner}</samlp:Response>\n")
    }

    #[test]
    fn spans_slice_from_lt_to_gt() {
        let xml = resp(
            r#"<saml:Assertion ID="a"><saml:Issuer>i &amp; j</saml:Issuer><saml:Empty x='1' /></saml:Assertion>"#,
        );
        let d = SamlDoc::parse(&xml).unwrap();
        for i in 0..d.len() {
            let s = &xml[d.node(i).start..d.node(i).end];
            assert!(s.starts_with('<') && s.ends_with('>'), "{s}");
        }
        let a = d.assertion().unwrap();
        assert_eq!(
            &xml[d.node(a).start..d.node(a).end],
            r#"<saml:Assertion ID="a"><saml:Issuer>i &amp; j</saml:Issuer><saml:Empty x='1' /></saml:Assertion>"#
        );
        let issuer = d.child_one(a, NS_ASSERT, "Issuer").unwrap();
        assert_eq!(d.leaf_text(issuer).unwrap(), "i & j");
        assert_eq!(
            &xml[d.node(issuer).start..d.node(issuer).end],
            "<saml:Issuer>i &amp; j</saml:Issuer>"
        );
    }

    #[test]
    fn rejects_hostile_structure() {
        let a = r#"<saml:Assertion ID="a"/>"#;
        let cases = [
            format!("<!DOCTYPE x>{}", resp(a)),
            resp(&format!("{a}<!-- c -->")),
            resp(&format!("{a}<?pi x?>")),
            resp(&format!("{a}{a}")),
            resp(r#"<saml:Assertion ID="a"/><saml:EncryptedAssertion/>"#),
            resp(r#"<saml:Assertion ID="a"><x ID="a"/></saml:Assertion>"#),
            resp(r#"<saml:Assertion ID="a" ID="b"/>"#),
            resp(r#"<saml:Assertion ID="a"/><saml:NameID>x</saml:NameID>"#),
            resp(r#"<x><saml:Assertion ID="a"/></x>"#),
            format!("{}<samlp:Response {R}/>", resp(a)),
            format!("{}junk", resp(a)),
            resp(r#"<saml:Assertion ID="a"/><u:X/>"#),
            resp(""),
            "<other/>".to_string(),
            "x".repeat(MAX_DOC_BYTES + 1),
        ];
        for c in cases {
            assert!(SamlDoc::parse(&c).is_err(), "accepted: {c}");
        }
        assert!(SamlDoc::parse(&resp(a)).is_ok());
    }

    #[test]
    fn structural_caps_and_xmlns_values() {
        let a = r#"<saml:Assertion ID="a"/>"#;
        let deep = format!(
            "{}{}",
            "<x:e xmlns:x=\"urn:x\">".repeat(MAX_DEPTH + 1),
            "</x:e>".repeat(MAX_DEPTH + 1)
        );
        assert!(SamlDoc::parse(&resp(&format!("{a}{deep}"))).is_err());
        let many = "<x:e xmlns:x=\"urn:x\"/>".repeat(MAX_ELEMENTS + 1);
        assert!(SamlDoc::parse(&resp(&format!("{a}{many}"))).is_err());
        let attrs: String = (0..=MAX_ATTRS).map(|i| format!(" a{i}=\"v\"")).collect();
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\"urn:x\"{attrs}/>"))).is_err());
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\"urn:x&amp;y\"/>"))).is_err());
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\" urn:x\"/>"))).is_err());
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\"urn:x\"/>"))).is_ok());
    }

    fn tree(inner: &str) -> SamlDoc {
        SamlDoc::parse(&resp(&format!(r#"<saml:Assertion ID="a"/>{inner}"#))).unwrap()
    }

    #[test]
    fn content_keeps_document_order() {
        let d = tree(r#"<x:e xmlns:x="urn:x">a<x:c/>b<![CDATA[<c>]]><x:d/>e</x:e>"#);
        let e = d.node(0).children[1];
        let n = d.node(e);
        assert_eq!(
            n.content,
            vec![
                Content::Text("a".into()),
                Content::Child(n.children[0]),
                Content::Text("b<c>".into()),
                Content::Child(n.children[1]),
                Content::Text("e".into()),
            ]
        );
        assert_eq!(n.text, "ab<c>e");
    }

    #[test]
    fn eol_and_attribute_normalisation() {
        let d = tree(
            "<x:e xmlns:x=\"urn:x\" a=\"1\t2\r\n3\n4\" b=\"1&#9;2&#10;3\">l1\r\nl2\rl3&#13;</x:e>",
        );
        let n = d.node(d.node(0).children[1]);
        assert_eq!(d.attr(d.node(0).children[1], "a"), Some("1 2 3 4"));
        assert_eq!(d.attr(d.node(0).children[1], "b"), Some("1\t2\n3"));
        assert_eq!(n.text, "l1\nl2\nl3\r");
    }

    #[test]
    fn rejects_bad_declarations_attributes_and_chars() {
        let bad = [
            r#"<x:e xmlns:x="urn:x" xmlns:xml="urn:y"/>"#,
            r#"<x:e xmlns:x="urn:x" xmlns:xmlns="urn:y"/>"#,
            r#"<x:e xmlns:x="urn:x" xmlns:p=""/>"#,
            r#"<x:e xmlns:x="urn:x" q:a="1"/>"#,
            r#"<x:e xmlns:x="urn:x" xmlns:p="urn:p" xmlns:q="urn:p" p:a="1" q:a="2"/>"#,
            r#"<x:e xmlns:x="urn:x">&#x1;</x:e>"#,
            r#"<x:e xmlns:x="urn:x" a="&#x1;"/>"#,
            r#"<x:e xmlns:x="urn:x" a="<"/>"#,
            "<x:e xmlns:x=\"urn:x\" xmlns:p=\"urn:a\tb\"/>",
            "<x:e xmlns:x=\"urn:x\" xmlns:p=\"urn:a b\"/>",
            "<x:e xmlns:x=\"urn:x\" xmlns:p=\"urn:a\u{7f}\"/>",
            r#"<x:e xmlns:x="urn:x" xmlns:="urn:y"/>"#,
            r#"<x:e xmlns:x="urn:x" x:="1"/>"#,
            r#"<x:e xmlns:x="urn:x" x:y:z="1"/>"#,
            r#"<x:e:f xmlns:x="urn:x"/>"#,
            r#"<x: xmlns:x="urn:x"/>"#,
            r#"<x:e xmlns:x="urn:x" 1a="1"/>"#,
        ];
        for b in bad {
            assert!(
                SamlDoc::parse(&resp(&format!(r#"<saml:Assertion ID="a"/>{b}"#))).is_err(),
                "accepted: {b}"
            );
        }
        // Distinct prefixes for distinct namespaces are fine, and xml: needs no declaration.
        let ok = r#"<x:e xmlns:x="urn:x" xmlns:p="urn:p" xmlns:q="urn:q" p:a="1" q:a="2" xml:lang="en"/>"#;
        assert!(SamlDoc::parse(&resp(&format!(r#"<saml:Assertion ID="a"/>{ok}"#))).is_ok());
    }

    #[test]
    fn ns_of_prefix_walks_ancestors() {
        let d = tree(
            r#"<x:e xmlns:x="urn:x" xmlns="urn:d"><x:y xmlns=""><z xmlns="urn:z"/></x:y></x:e>"#,
        );
        let e = d.node(0).children[1];
        let y = d.node(e).children[0];
        let z = d.node(y).children[0];
        assert_eq!(d.ns_of_prefix(e, "x"), Some("urn:x"));
        assert_eq!(d.ns_of_prefix(z, "x"), Some("urn:x"));
        assert_eq!(d.ns_of_prefix(e, ""), Some("urn:d"));
        assert_eq!(d.ns_of_prefix(y, ""), None);
        assert_eq!(d.ns_of_prefix(z, ""), Some("urn:z"));
        assert_eq!(d.ns_of_prefix(e, "xml"), Some(NS_XML));
        assert_eq!(d.ns_of_prefix(e, "nope"), None);
        assert_eq!(d.ns_of_prefix(0, "saml"), Some(NS_ASSERT));
    }
}
