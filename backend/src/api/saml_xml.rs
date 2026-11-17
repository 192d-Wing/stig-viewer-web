//! Strict, single-pass XML front end for SAMLResponse documents.
//!
//! The document is parsed exactly once with `quick-xml` into an index of
//! elements (namespace, local name, attributes, parent, byte span). Both
//! signature verification (`saml_verify`) and identity extraction (`saml`)
//! work from this one tree, so the element whose signature is verified is
//! the same element the identity is read from.
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
    anyhow::Error::new(Reject { code, detail: detail.into() })
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

#[derive(Debug)]
pub struct Node {
    pub ns: String,
    pub local: String,
    /// Element prefix as written ("" for unprefixed).
    pub prefix: String,
    /// Namespace prefixes declared on this element ("" is the default namespace).
    pub decls: Vec<String>,
    /// Prefixes used by this element's attributes (excluding `xmlns`/`xml`).
    pub attr_prefixes: Vec<String>,
    /// Raw attributes by qualified key (only unprefixed keys are ever looked up).
    pub attrs: Vec<(String, String)>,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Byte offsets into the source: `start` at `<`, `end` just past the final `>`.
    pub start: usize,
    pub end: usize,
    /// Concatenated direct text and CDATA.
    pub text: String,
}

#[derive(Debug)]
pub struct SamlDoc {
    src: String,
    nodes: Vec<Node>,
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
    let (prefix, local) = match name.split_once(':') {
        Some((p, l)) => (p.to_string(), l.to_string()),
        None => (String::new(), name),
    };
    let (mut attrs, mut decls, mut attr_prefixes) = (Vec::new(), Vec::new(), Vec::new());
    for a in e.attributes() {
        if attrs.len() >= MAX_ATTRS {
            bail!("too many attributes");
        }
        let a = a.map_err(|e| anyhow!("bad attribute: {e}"))?;
        let key = std::str::from_utf8(a.key.as_ref())
            .map_err(|_| anyhow!("attribute name not utf-8"))?
            .to_string();
        let val = a
            .unescape_value()
            .map_err(|e| anyhow!("bad attribute value: {e}"))?
            .to_string();
        if key == "xmlns" || key.starts_with("xmlns:") {
            if a.value.contains(&b'&') || val != val.trim() {
                bail!("namespace declaration value not accepted");
            }
            decls.push(key.strip_prefix("xmlns:").unwrap_or("").to_string());
        } else if let Some((p, _)) = key.split_once(':') {
            if p != "xml" {
                attr_prefixes.push(p.to_string());
            }
        }
        attrs.push((key, val));
    }
    Ok(Node {
        ns,
        local,
        prefix,
        decls,
        attr_prefixes,
        attrs,
        parent,
        children: Vec::new(),
        start,
        end,
        text: String::new(),
    })
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
            "Subject" | "NameID" | "EncryptedID" | "AttributeStatement" | "Attribute" | "AttributeValue"
        )
    {
        bail!("identity element {} outside Assertion", n.local);
    }
    let idx = nodes.len();
    if let Some(p) = n.parent {
        nodes[p].children.push(idx);
    }
    nodes.push(n);
    Ok(idx)
}

impl SamlDoc {
    pub fn parse(xml: &str) -> Result<SamlDoc> {
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
                    let s = t.unescape().map_err(|e| anyhow!("bad text: {e}"))?;
                    match stack.last() {
                        Some(&i) => nodes[i].text.push_str(&s),
                        None if s.trim().is_empty() => {}
                        None => bail!("text outside root element"),
                    }
                }
                Event::CData(c) => {
                    let s = std::str::from_utf8(&c).map_err(|_| anyhow!("CDATA not utf-8"))?;
                    match stack.last() {
                        Some(&i) => nodes[i].text.push_str(s),
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
        let doc = SamlDoc { src: xml.to_string(), nodes };
        doc.validate()?;
        Ok(doc)
    }

    fn validate(&self) -> Result<()> {
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

    /// Exact source text of element `i`, `<` through `>`.
    pub fn span(&self, i: usize) -> &str {
        &self.src[self.nodes[i].start..self.nodes[i].end]
    }

    /// Source text of element `i` with the span of its descendant `excise` removed.
    pub fn span_without(&self, i: usize, excise: usize) -> String {
        let (s, e) = (self.nodes[i].start, self.nodes[i].end);
        let (xs, xe) = (self.nodes[excise].start, self.nodes[excise].end);
        format!("{}{}", &self.src[s..xs], &self.src[xe..e])
    }

    /// True when every prefix (and the default namespace, for unprefixed
    /// elements) used within element `i` is declared inside it, so the
    /// element's bytes alone fix the namespace of everything they cover.
    /// The subtree of `skip` (an excised enveloped Signature) is not checked.
    pub fn namespaces_closed(&self, i: usize, skip: Option<usize>) -> bool {
        fn walk(d: &SamlDoc, i: usize, skip: Option<usize>, scope: &mut Vec<String>) -> bool {
            if Some(i) == skip {
                return true;
            }
            let n = &d.nodes[i];
            let mark = scope.len();
            scope.extend(n.decls.iter().cloned());
            let ok = scope.contains(&n.prefix)
                && n.attr_prefixes.iter().all(|p| scope.contains(p))
                && n.children.iter().all(|&c| walk(d, c, skip, scope));
            scope.truncate(mark);
            ok
        }
        walk(self, i, skip, &mut Vec::new())
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
        let xml = resp(r#"<saml:Assertion ID="a"><saml:Issuer>i &amp; j</saml:Issuer><saml:Empty x='1' /></saml:Assertion>"#);
        let d = SamlDoc::parse(&xml).unwrap();
        for i in 0..d.len() {
            let s = d.span(i);
            assert!(s.starts_with('<') && s.ends_with('>'), "{s}");
        }
        let a = d.assertion().unwrap();
        assert_eq!(d.span(a), r#"<saml:Assertion ID="a"><saml:Issuer>i &amp; j</saml:Issuer><saml:Empty x='1' /></saml:Assertion>"#);
        let issuer = d.child_one(a, NS_ASSERT, "Issuer").unwrap();
        assert_eq!(d.leaf_text(issuer).unwrap(), "i & j");
        assert_eq!(d.span(issuer), "<saml:Issuer>i &amp; j</saml:Issuer>");
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
            resp("") ,
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
        let deep = format!("{}{}", "<x:e xmlns:x=\"urn:x\">".repeat(MAX_DEPTH + 1), "</x:e>".repeat(MAX_DEPTH + 1));
        assert!(SamlDoc::parse(&resp(&format!("{a}{deep}"))).is_err());
        let many = "<x:e xmlns:x=\"urn:x\"/>".repeat(MAX_ELEMENTS + 1);
        assert!(SamlDoc::parse(&resp(&format!("{a}{many}"))).is_err());
        let attrs: String = (0..=MAX_ATTRS).map(|i| format!(" a{i}=\"v\"")).collect();
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\"urn:x\"{attrs}/>"))).is_err());
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\"urn:x&amp;y\"/>"))).is_err());
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\" urn:x\"/>"))).is_err());
        assert!(SamlDoc::parse(&resp(&format!("{a}<x:e xmlns:x=\"urn:x\"/>"))).is_ok());
    }

    #[test]
    fn namespaces_closed_requires_inner_declarations() {
        let ok = resp(r#"<saml:Assertion ID="a" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer/></saml:Assertion>"#);
        let d = SamlDoc::parse(&ok).unwrap();
        assert!(d.namespaces_closed(d.assertion().unwrap(), None));
        // Assertion relies on the prefix declared on the Response.
        let d = SamlDoc::parse(&resp(r#"<saml:Assertion ID="a"/>"#)).unwrap();
        assert!(!d.namespaces_closed(d.assertion().unwrap(), None));
        assert!(d.namespaces_closed(d.root(), None));
    }
}
