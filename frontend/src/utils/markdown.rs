//! Tiny purpose-built markdown renderer for per-asset runbooks.
//!
//! Operational runbook content is small and conventional: a handful of
//! headings, bullet/numbered lists, the occasional code fence, some
//! bold/italic for emphasis, and bare URLs. That's it. Pulling in a full
//! CommonMark parser to render this is way too much rope, so this module
//! hand-rolls a renderer that supports exactly that subset.
//!
//! What is supported
//! -----------------
//!   - `## Heading`, `### Heading`           → `<h2>`, `<h3>`
//!   - `**bold**`                            → `<strong>`
//!   - `*italic*`                            → `<em>`
//!   - `` `inline code` ``                   → `<code>`
//!   - `- item`, `* item`                    → `<ul><li>`
//!   - `1. item`, `2. item`                  → `<ol><li>`
//!   - Triple-backtick fences                → `<pre><code>` (no highlighting)
//!   - Blank-line separated text             → `<p>`
//!   - Bare http(s) URLs                     → `<a target="_blank" rel="noopener noreferrer">`
//!
//! What is intentionally not supported
//! -----------------------------------
//!   - Tables, blockquotes, images, footnotes
//!   - Setext headings, h1/h4+
//!   - Reference-style links
//!   - Inline HTML — escaped on the way in
//!
//! Escape policy
//! -------------
//! Input is always treated as untrusted. We HTML-escape every text token
//! before assembling the output, and the URL autolinker emits its own
//! escaped href + text content. The only "raw" HTML is the tag shell we
//! construct ourselves.
//!
//! Public surface
//! --------------
//! `render_markdown(src)` returns an HTML string suitable for handing to
//! `Html::from_html_unchecked`.

use super::parse_xccdf::{is_js_whitespace, js_trim};

/// HTML-escape `s` for safe inclusion as text or attribute content.
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap every `<delim>text<delim>` span in `<tag>`, where `text` is one or
/// more characters that contain no `marker` (the delimiter's character).
/// Equivalent to `s.replace(/DELIM([^M]+)DELIM/g, '<tag>$1</tag>')`.
fn wrap_spans(s: &str, delim: &str, marker: char, tag: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find(delim) {
        let after = &rest[start + delim.len()..];
        // `[^M]+` is greedy and cannot cross a marker, so the span has to
        // close at the very next marker, and must not be empty.
        match after.find(marker) {
            Some(len) if len > 0 && after[len..].starts_with(delim) => {
                out.push_str(&rest[..start]);
                out.push_str(&format!("<{tag}>{}</{tag}>", &after[..len]));
                rest = &after[len + delim.len()..];
            }
            _ => {
                // No match starting here: emit one character and retry.
                let step = start + rest[start..].chars().next().map_or(1, char::len_utf8);
                out.push_str(&rest[..step]);
                rest = &rest[step..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Characters a URL may contain: `[^\s<>"')]`.
fn is_url_char(c: char) -> bool {
    !is_js_whitespace(c) && !matches!(c, '<' | '>' | '"' | '\'' | ')')
}

/// Characters a URL may end with: `[^\s<>"'.,;:!?)]`.
fn is_url_end_char(c: char) -> bool {
    is_url_char(c) && !matches!(c, '.' | ',' | ';' | ':' | '!' | '?')
}

/// If a bare URL starts at the beginning of `s`, return its byte length.
/// Matches `https?:\/\/[^\s<>"')]+[^\s<>"'.,;:!?)]`.
fn url_len_at(s: &str) -> Option<usize> {
    let scheme_len = ["https://", "http://"].iter().find(|p| s.starts_with(**p))?.len();
    let body = &s[scheme_len..];
    // Longest run of URL characters, then back off to the last character
    // that may end a URL; at least one character must precede it.
    let run_len = body.find(|c| !is_url_char(c)).unwrap_or(body.len());
    let (last_idx, last) = body[..run_len]
        .char_indices()
        .skip(1)
        .filter(|(_, c)| is_url_end_char(*c))
        .last()?;
    Some(scheme_len + last_idx + last.len_utf8())
}

/// Autolink bare http(s) URLs. Equivalent to replacing
/// `/(^|[^"])(https?:\/\/…)/g` — a URL directly preceded by `"` is skipped.
fn autolink(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while pos < s.len() {
        // `^` alternative: a URL at the very start of the string.
        let (pre_len, url_len) = match (pos == 0).then(|| url_len_at(s)).flatten() {
            Some(url_len) => (0, Some(url_len)),
            None => {
                // `[^"]` alternative: any other character, then the URL.
                let c = s[pos..].chars().next().unwrap_or('\0');
                let pre_len = c.len_utf8();
                let url_len = if c == '"' { None } else { url_len_at(&s[pos + pre_len..]) };
                (pre_len, url_len)
            }
        };
        out.push_str(&s[pos..pos + pre_len]);
        pos += pre_len;
        if let Some(url_len) = url_len {
            let url = &s[pos..pos + url_len];
            out.push_str(&format!(
                "<a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">{url}</a>"
            ));
            pos += url_len;
        }
    }
    out
}

/// Apply inline transforms to already-escaped text: code spans, bold,
/// italic, and bare URLs. Order matters — code spans first so we don't
/// accidentally bold-ify text inside a `code` block, URLs last so we don't
/// try to autolink anything we've already wrapped.
///
/// The functions all operate on the escaped input; the patterns are
/// therefore safe to run against literal `&lt;` / `&amp;` sequences (they
/// just won't match).
fn apply_inline(escaped: &str) -> String {
    // Inline code: `text`, anchored to a single backtick pair on each side.
    // Run before bold/italic.
    let out = wrap_spans(escaped, "`", '`', "code");

    // Bold: **text**. Consecutive bolds on the same line each match separately.
    let out = wrap_spans(&out, "**", '*', "strong");

    // Italic: *text*. Must come after the bold pass — the bold pass has
    // already consumed any `**…**` runs.
    let out = wrap_spans(&out, "*", '*', "em");

    // Bare URLs. Only http(s). Stop at whitespace or common trailing
    // punctuation (the last char often belongs to the surrounding sentence,
    // not the URL). Avoid matching inside existing tags by skipping any URL
    // preceded by `"` (i.e. already a href attribute).
    autolink(&out)
}

/// For `MARKER\s+(.+)$`: given the text after the marker, require at least
/// one whitespace character and return the captured remainder. `.` does not
/// match line terminators, so a stray one in the remainder is no match.
fn after_whitespace(rest: &str) -> Option<&str> {
    let text = rest.trim_start_matches(is_js_whitespace);
    let has_gap = text.len() < rest.len();
    let single_line = !text.contains(['\n', '\r', '\u{2028}', '\u{2029}']);
    (has_gap && !text.is_empty() && single_line).then_some(text)
}

/// `^(##+)\s+(.+)$` restricted to two or three hashes → (level, text).
fn parse_heading(line: &str) -> Option<(usize, &str)> {
    let level = line.len() - line.trim_start_matches('#').len();
    // Anything h4+ falls through to paragraph (deliberately — runbooks don't
    // need it and treating `####` as a paragraph keeps the parser simple).
    if level != 2 && level != 3 {
        return None;
    }
    after_whitespace(&line[level..]).map(|text| (level, text))
}

/// Unordered list item: `- text` or `* text`.
fn parse_unordered_item(line: &str) -> Option<&str> {
    line.strip_prefix(['-', '*']).and_then(after_whitespace)
}

/// Ordered list item: `1. text`. Any positive integer is fine.
fn parse_ordered_item(line: &str) -> Option<&str> {
    let rest = line.trim_start_matches(|c: char| c.is_ascii_digit());
    if rest.len() == line.len() {
        return None;
    }
    rest.strip_prefix('.').and_then(after_whitespace)
}

/// `src.split(/\r?\n/)`: split on LF, dropping a CR that directly precedes it.
fn split_lines(src: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = src.split('\n').collect();
    if let Some((_last, terminated)) = lines.split_last_mut() {
        for line in terminated {
            *line = line.strip_suffix('\r').unwrap_or(line);
        }
    }
    lines
}

/// Line-oriented renderer state: a tiny mode stack (paragraph open, list
/// open) plus the accumulated output.
#[derive(Default)]
struct Renderer<'a> {
    out: String,
    in_ul: bool,
    in_ol: bool,
    para_buf: Vec<&'a str>,
}

impl Renderer<'_> {
    fn flush_para(&mut self) {
        if self.para_buf.is_empty() {
            return;
        }
        let joined = self.para_buf.join(" ");
        self.out.push_str(&format!("<p>{}</p>", apply_inline(&escape_html(&joined))));
        self.para_buf.clear();
    }

    fn close_ul(&mut self) {
        if self.in_ul {
            self.out.push_str("</ul>");
            self.in_ul = false;
        }
    }

    fn close_ol(&mut self) {
        if self.in_ol {
            self.out.push_str("</ol>");
            self.in_ol = false;
        }
    }

    fn close_lists(&mut self) {
        self.close_ul();
        self.close_ol();
    }

    fn push_item(&mut self, text: &str) {
        self.out.push_str(&format!("<li>{}</li>", apply_inline(&escape_html(text))));
    }

    fn push_fence(&mut self, fence_buf: &[&str]) {
        self.out
            .push_str(&format!("<pre><code>{}</code></pre>", escape_html(&fence_buf.join("\n"))));
    }
}

/// Render the supported markdown subset to a sanitised HTML string. See the
/// module doc for the exact supported subset.
///
/// The parser is line-oriented: we walk the input one line at a time and
/// maintain a tiny mode stack (paragraph open, list open, fence open). It's
/// not a full CommonMark implementation but it handles the realistic runbook
/// shapes without any edge-case explosions.
pub fn render_markdown(src: &str) -> String {
    if src.is_empty() {
        return String::new();
    }

    let mut r = Renderer::default();
    let mut in_fence = false;
    let mut fence_buf: Vec<&str> = Vec::new();

    for raw in split_lines(src) {
        // Fenced code block — strictly triple-backtick at the start of the
        // line; the language tag is ignored (no highlighting).
        if raw.starts_with("```") {
            if in_fence {
                // Closing fence. Emit the buffered content as a single <pre>.
                r.push_fence(&fence_buf);
                fence_buf.clear();
                in_fence = false;
            } else {
                // Opening fence. Close any open paragraph / list first so the
                // <pre> is a top-level sibling.
                r.flush_para();
                r.close_lists();
                in_fence = true;
            }
            continue;
        }
        if in_fence {
            fence_buf.push(raw);
            continue;
        }

        let line = raw.trim_end_matches(is_js_whitespace);

        // Blank line — paragraph / list boundary.
        if js_trim(line).is_empty() {
            r.flush_para();
            r.close_lists();
            continue;
        }

        if let Some((level, text)) = parse_heading(line) {
            r.flush_para();
            r.close_lists();
            r.out.push_str(&format!("<h{level}>{}</h{level}>", apply_inline(&escape_html(text))));
            continue;
        }

        if let Some(text) = parse_unordered_item(line) {
            r.flush_para();
            r.close_ol();
            if !r.in_ul {
                r.out.push_str("<ul>");
                r.in_ul = true;
            }
            r.push_item(text);
            continue;
        }

        if let Some(text) = parse_ordered_item(line) {
            r.flush_para();
            r.close_ul();
            if !r.in_ol {
                r.out.push_str("<ol>");
                r.in_ol = true;
            }
            r.push_item(text);
            continue;
        }

        // Default: accumulate into the open paragraph. Mid-paragraph lines
        // are joined with a space to mimic CommonMark soft-break behavior;
        // an actual paragraph break needs a blank line.
        r.close_lists();
        r.para_buf.push(line);
    }

    // Drain any open state at EOF.
    if in_fence {
        r.push_fence(&fence_buf);
    }
    r.flush_para();
    r.close_lists();

    r.out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_renders_nothing() {
        assert_eq!(render_markdown(""), "");
        assert_eq!(render_markdown("\n\n  \n"), "");
    }

    // The two runbooks e2e/76-asset-runbook.spec.js drives through the UI.
    #[test]
    fn renders_the_e2e_runbook() {
        assert_eq!(
            render_markdown("## Steps\n- Restart nginx\n- Verify port 443"),
            "<h2>Steps</h2><ul><li>Restart nginx</li><li>Verify port 443</li></ul>"
        );
    }

    #[test]
    fn renders_the_e2e_smoke_sample() {
        let sample = [
            "## H2 heading",
            "### H3 heading",
            "",
            "Plain paragraph with **bold** and *italic* and `inline code`.",
            "",
            "- bullet one",
            "- bullet two",
            "",
            "1. first",
            "2. second",
            "",
            "Visit https://example.gov/runbook for details.",
            "",
            "```",
            "fenced code line",
            "```",
        ]
        .join("\n");
        assert_eq!(
            render_markdown(&sample),
            "<h2>H2 heading</h2><h3>H3 heading</h3>\
             <p>Plain paragraph with <strong>bold</strong> and <em>italic</em> and <code>inline code</code>.</p>\
             <ul><li>bullet one</li><li>bullet two</li></ul>\
             <ol><li>first</li><li>second</li></ol>\
             <p>Visit <a href=\"https://example.gov/runbook\" target=\"_blank\" rel=\"noopener noreferrer\">https://example.gov/runbook</a> for details.</p>\
             <pre><code>fenced code line</code></pre>"
        );
    }

    #[test]
    fn escapes_html_and_never_links_other_schemes() {
        assert_eq!(
            render_markdown("<script>alert('x')</script> & \"q\" [x](javascript:alert(1)) ftp://x.y"),
            "<p>&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;q&quot; [x](javascript:alert(1)) ftp://x.y</p>"
        );
    }

    #[test]
    fn only_h2_and_h3_are_headings() {
        assert_eq!(
            render_markdown("# h1\n#### h4\n##nospace\n##   spaced  "),
            "<p># h1 #### h4 ##nospace</p><h2>spaced</h2>"
        );
    }

    #[test]
    fn paragraphs_join_soft_breaks_and_handle_crlf() {
        assert_eq!(render_markdown("text\nmore\r\n\r\nlast"), "<p>text more</p><p>last</p>");
    }

    #[test]
    fn list_kinds_switch_and_close() {
        assert_eq!(
            render_markdown("- a\n* b\n1. c\n12. d\n- e\npara\n- f\n## h"),
            "<ul><li>a</li><li>b</li></ul><ol><li>c</li><li>d</li></ol><ul><li>e</li></ul>\
             <p>para</p><ul><li>f</li></ul><h2>h</h2>"
        );
        assert_eq!(render_markdown("-nospace\n1.nospace\n1) paren"), "<p>-nospace 1.nospace 1) paren</p>");
    }

    #[test]
    fn fences_are_verbatim_and_drain_at_eof() {
        assert_eq!(
            render_markdown("para\n```js\nlet a = '<b>';\n  **not bold**\n\n- no list\n```\nafter"),
            "<p>para</p><pre><code>let a = &#39;&lt;b&gt;&#39;;\n  **not bold**\n\n- no list</code></pre><p>after</p>"
        );
        assert_eq!(render_markdown("```\nunclosed `x`"), "<pre><code>unclosed `x`</code></pre>");
        assert_eq!(render_markdown("a\n```"), "<p>a</p><pre><code></code></pre>");
    }

    #[test]
    fn inline_spans_follow_the_regex_semantics() {
        assert_eq!(apply_inline("`a` `` `b*c*`"), "<code>a</code> `<code> </code>b<em>c</em>`");
        assert_eq!(apply_inline("**a** **b**"), "<strong>a</strong> <strong>b</strong>");
        assert_eq!(apply_inline("***x***"), "<em><strong>x</strong></em>");
        assert_eq!(apply_inline("**a*b**"), "*<em>a</em>b**");
        assert_eq!(apply_inline("* ** `"), "<em> </em>* `");
        assert_eq!(apply_inline("** `` *"), "*<em> `` </em>");
        assert_eq!(apply_inline("2 * 3 * 4"), "2 <em> 3 </em> 4");
    }

    #[test]
    fn autolinks_trim_trailing_punctuation() {
        let a = |url: &str| {
            format!("<a href=\"{url}\" target=\"_blank\" rel=\"noopener noreferrer\">{url}</a>")
        };
        assert_eq!(autolink("https://a.b/c."), format!("{}.", a("https://a.b/c")));
        assert_eq!(autolink("(http://a.b/c?d=e&amp;f=g)!"), format!("({})!", a("http://a.b/c?d=e&amp;f=g")));
        assert_eq!(autolink("x https://a.b, y"), format!("x {}, y", a("https://a.b")));
        // Preceded by a double quote (an existing href): left alone.
        assert_eq!(autolink("\"https://a.b"), "\"https://a.b");
        // Too short to be a URL.
        assert_eq!(autolink("https:// http://x https://."), "https:// http://x https://.");
        assert_eq!(autolink("http://xy"), a("http://xy"));
        assert_eq!(
            apply_inline("`https://in.code/x`"),
            format!("<code>{}</code>", a("https://in.code/x"))
        );
    }
}
