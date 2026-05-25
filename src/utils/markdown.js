/**
 * Tiny purpose-built markdown renderer for per-asset runbooks.
 *
 * Operational runbook content is small and conventional: a handful of
 * headings, bullet/numbered lists, the occasional code fence, some
 * bold/italic for emphasis, and bare URLs. That's it. Pulling in
 * `react-markdown` (~50 KB) plus a CommonMark parser to render this
 * is way too much rope, so this module hand-rolls a renderer that
 * supports exactly that subset.
 *
 * What is supported
 * -----------------
 *   - `## Heading`, `### Heading`           → <h2>, <h3>
 *   - `**bold**`                            → <strong>
 *   - `*italic*`                            → <em>
 *   - `` `inline code` ``                   → <code>
 *   - `- item`, `* item`                    → <ul><li>
 *   - `1. item`, `2. item`                  → <ol><li>
 *   - Triple-backtick fences                → <pre><code> (no highlighting)
 *   - Blank-line separated text             → <p>
 *   - Bare http(s) URLs                     → <a target="_blank" rel="noopener noreferrer">
 *
 * What is intentionally not supported
 * -----------------------------------
 *   - Tables, blockquotes, images, footnotes
 *   - Setext headings, h1/h4+
 *   - Reference-style links
 *   - Inline HTML — escaped on the way in
 *
 * Escape policy
 * -------------
 * Input is always treated as untrusted. We HTML-escape every text
 * token before assembling the output, and the URL autolinker emits
 * its own escaped href + textContent. The only "raw" HTML is the
 * tag shell we construct ourselves.
 *
 * Public surface
 * --------------
 * `renderMarkdown(src)` returns an HTML string suitable for handing
 * to `dangerouslySetInnerHTML`. Returning a string (rather than
 * React nodes) keeps the module zero-dep and trivially testable from
 * Playwright via `page.evaluate`.
 */

/** HTML-escape `s` for safe inclusion as text or attribute content. */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Apply inline transforms to already-escaped text: code spans, bold,
 * italic, and bare URLs. Order matters — code spans first so we
 * don't accidentally bold-ify text inside a `code` block, URLs last
 * so we don't try to autolink anything we've already wrapped.
 *
 * The functions all operate on the escaped input; the regexes are
 * therefore safe to run against literal `&lt;` / `&amp;` sequences
 * (they just won't match).
 */
function applyInline(escaped) {
  let out = escaped;

  // Inline code: `text`. Must be greedy-anchored to a single backtick
  // pair on each side. Run before bold/italic so the inner content
  // isn't re-interpreted.
  out = out.replace(/`([^`]+)`/g, (_m, c) => `<code>${c}</code>`);

  // Bold: **text**. Non-greedy so consecutive bolds on the same line
  // each match separately.
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");

  // Italic: *text*. Must come after the bold pass — the bold regex
  // has already consumed any `**…**` runs.
  out = out.replace(/\*([^*]+)\*/g, "<em>$1</em>");

  // Bare URLs. Only http(s). Stop at whitespace or common trailing
  // punctuation (the last char often belongs to the surrounding
  // sentence, not the URL). Avoid matching inside existing tags by
  // skipping any URL preceded by `"` (i.e. already a href attribute).
  out = out.replace(
    /(^|[^"])(https?:\/\/[^\s<>"')]+[^\s<>"'.,;:!?)])/g,
    (_m, pre, url) =>
      `${pre}<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`,
  );

  return out;
}

/**
 * Render a markdown string to an HTML string. See module doc for the
 * exact supported subset.
 *
 * The parser is line-oriented: we walk the input one line at a time
 * and maintain a tiny mode stack (paragraph open, list open, fence
 * open). It's not a full CommonMark implementation but it handles
 * the realistic runbook shapes without any edge-case explosions.
 */
export function renderMarkdown(src) {
  if (src == null || src === "") return "";
  const lines = String(src).split(/\r?\n/);

  const out = [];
  let inFence = false;
  let fenceBuf = [];
  let inUl = false;
  let inOl = false;
  let paraBuf = [];

  const flushPara = () => {
    if (paraBuf.length === 0) return;
    const joined = paraBuf.join(" ");
    out.push(`<p>${applyInline(escapeHtml(joined))}</p>`);
    paraBuf = [];
  };
  const closeUl = () => {
    if (inUl) {
      out.push("</ul>");
      inUl = false;
    }
  };
  const closeOl = () => {
    if (inOl) {
      out.push("</ol>");
      inOl = false;
    }
  };
  const closeLists = () => {
    closeUl();
    closeOl();
  };

  for (const raw of lines) {
    // Fenced code block — strictly triple-backtick, anywhere on the
    // line is fine but we ignore the language tag (no highlighting).
    if (/^```/.test(raw)) {
      if (inFence) {
        // Closing fence. Emit the buffered content as a single <pre>.
        out.push(`<pre><code>${escapeHtml(fenceBuf.join("\n"))}</code></pre>`);
        fenceBuf = [];
        inFence = false;
      } else {
        // Opening fence. Close any open paragraph / list first so the
        // <pre> is a top-level sibling.
        flushPara();
        closeLists();
        inFence = true;
      }
      continue;
    }
    if (inFence) {
      fenceBuf.push(raw);
      continue;
    }

    const line = raw.replace(/\s+$/u, "");

    // Blank line — paragraph / list boundary.
    if (line.trim() === "") {
      flushPara();
      closeLists();
      continue;
    }

    // Heading: ## or ###. Anything h4+ falls through to paragraph
    // (deliberately — runbooks don't need it and treating `####` as
    // a paragraph keeps the parser simple).
    let m = /^(##+)\s+(.+)$/.exec(line);
    if (m && (m[1].length === 2 || m[1].length === 3)) {
      flushPara();
      closeLists();
      const level = m[1].length; // 2 → h2, 3 → h3
      out.push(`<h${level}>${applyInline(escapeHtml(m[2]))}</h${level}>`);
      continue;
    }

    // Unordered list item: `- text` or `* text`.
    m = /^[-*]\s+(.+)$/.exec(line);
    if (m) {
      flushPara();
      closeOl();
      if (!inUl) {
        out.push("<ul>");
        inUl = true;
      }
      out.push(`<li>${applyInline(escapeHtml(m[1]))}</li>`);
      continue;
    }

    // Ordered list item: `1. text`. Any positive integer is fine.
    m = /^\d+\.\s+(.+)$/.exec(line);
    if (m) {
      flushPara();
      closeUl();
      if (!inOl) {
        out.push("<ol>");
        inOl = true;
      }
      out.push(`<li>${applyInline(escapeHtml(m[1]))}</li>`);
      continue;
    }

    // Default: accumulate into the open paragraph. Mid-paragraph
    // lines are joined with a space to mimic CommonMark soft-break
    // behavior; an actual paragraph break needs a blank line.
    closeLists();
    paraBuf.push(line);
  }

  // Drain any open state at EOF.
  if (inFence) {
    out.push(`<pre><code>${escapeHtml(fenceBuf.join("\n"))}</code></pre>`);
  }
  flushPara();
  closeLists();

  return out.join("");
}
