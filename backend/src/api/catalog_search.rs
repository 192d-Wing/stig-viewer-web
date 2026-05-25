//! Cross-rule full-text search across the STIG catalog.
//!
//! `/api/catalog/search?q=<query>&limit=<N>` does a case-insensitive
//! substring match against:
//!   - STIG titles (score 10)
//!   - Rule IDs — exact match score 8, substring score 3
//!   - Rule titles (score 5)
//!
//! For each catalog row we already know the STIG title (from the
//! `stigs_catalog` table). When the title doesn't match the query we
//! crack open the on-disk JSON at `${data_dir}/stigs/{id}.json` to scan
//! rule ids and titles. ~158 small files; reading them lazily is fine
//! and avoids building a DB index for v1.
//!
//! Snippets get a `<mark>…</mark>` wrapper around the matched term so
//! the frontend can highlight without re-running the matcher. Each
//! snippet is capped at 200 chars after markup; the whole response is
//! belt-and-braces capped at 5 MB.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::db::list_catalog;
use crate::AppState;

const MIN_QUERY_LEN: usize = 2;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
const SNIPPET_CONTEXT: usize = 20;
const MAX_SNIPPET_LEN: usize = 200;
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchQuery {
    pub q: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    pub stig_id: String,
    pub stig_title: String,
    pub rule_id: Option<String>,
    /// One of: "stigTitle", "ruleId", "ruleTitle".
    pub field: String,
    /// HTML-ish snippet — contains `<mark>…</mark>` around the match,
    /// no other tags.
    pub snippet: String,
    pub score: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    pub query: String,
    pub results: Vec<SearchHit>,
}

/// Subset of the on-disk STIG JSON needed for rule-level search.
/// Kept narrow so additions to the canonical shape don't break parsing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchStig {
    #[serde(default)]
    rules: Vec<SearchRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
}

/// GET /api/catalog/search?q=…&limit=N
pub async fn search_handler(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, StatusCode> {
    let raw_q = params.q.unwrap_or_default();
    let q = raw_q.trim();
    if q.chars().count() < MIN_QUERY_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);

    let entries = list_catalog(state.pool.as_ref(), None).await.map_err(|e| {
        tracing::error!("catalog search: list_catalog failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let q_lower = q.to_lowercase();
    let mut hits: Vec<SearchHit> = Vec::new();

    for entry in &entries {
        // 1) Match on stig title — cheap, no I/O.
        let title_lower = entry.title.to_lowercase();
        let title_matched = title_lower.contains(&q_lower);
        if title_matched {
            hits.push(SearchHit {
                stig_id: entry.id.clone(),
                stig_title: entry.title.clone(),
                rule_id: None,
                field: "stigTitle".to_string(),
                snippet: build_snippet(&entry.title, q),
                score: 10,
            });
        }

        // 2) Crack open the JSON to scan rule ids + titles. We always
        //    scan so a query that matches both title and a rule still
        //    surfaces individual rule hits — useful for "edge" where
        //    operators want to jump to specific rules.
        let path = state
            .config
            .data_dir
            .join("stigs")
            .join(format!("{}.json", entry.id));
        // tokio::fs is async-aware but we'd block on each iteration
        // anyway; spawn_blocking would be overkill for ~158 small files.
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Catalog row without a file on disk (shouldn't happen
                // in normal flows but tolerate it rather than 500).
                tracing::warn!(
                    "catalog search: missing JSON for {} at {}",
                    entry.id,
                    path.display()
                );
                continue;
            }
            Err(e) => {
                tracing::error!(
                    "catalog search: read {} failed: {e:#}",
                    path.display()
                );
                continue;
            }
        };
        let stig: SearchStig = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    "catalog search: parse {} failed: {e:#}",
                    path.display()
                );
                continue;
            }
        };

        for rule in &stig.rules {
            let rid_lower = rule.id.to_lowercase();
            let rtitle_lower = rule.title.to_lowercase();
            // Rule id exact takes precedence over substring.
            if rid_lower == q_lower {
                hits.push(SearchHit {
                    stig_id: entry.id.clone(),
                    stig_title: entry.title.clone(),
                    rule_id: Some(rule.id.clone()),
                    field: "ruleId".to_string(),
                    snippet: build_snippet(&rule.id, q),
                    score: 8,
                });
            } else if rid_lower.contains(&q_lower) {
                hits.push(SearchHit {
                    stig_id: entry.id.clone(),
                    stig_title: entry.title.clone(),
                    rule_id: Some(rule.id.clone()),
                    field: "ruleId".to_string(),
                    snippet: build_snippet(&rule.id, q),
                    score: 3,
                });
            }
            if rtitle_lower.contains(&q_lower) {
                hits.push(SearchHit {
                    stig_id: entry.id.clone(),
                    stig_title: entry.title.clone(),
                    rule_id: Some(rule.id.clone()),
                    field: "ruleTitle".to_string(),
                    snippet: build_snippet(&rule.title, q),
                    score: 5,
                });
            }
        }
    }

    // Score desc, then alphabetic by (stig title, rule id, field).
    hits.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.stig_title.cmp(&b.stig_title))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.field.cmp(&b.field))
    });
    hits.truncate(limit);

    let response = SearchResponse {
        query: q.to_string(),
        results: hits,
    };

    // Belt-and-braces size cap. If we somehow blew past 5MB drop
    // trailing rows until we fit. Practically unreachable with the
    // snippet + limit caps above, but cheap insurance.
    let mut bytes = serde_json::to_vec(&response).map_err(|e| {
        tracing::error!("catalog search: serialise failed: {e:#}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        let mut trimmed = response;
        while bytes.len() > MAX_RESPONSE_BYTES && !trimmed.results.is_empty() {
            trimmed.results.pop();
            bytes = serde_json::to_vec(&trimmed).map_err(|e| {
                tracing::error!("catalog search: re-serialise failed: {e:#}");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        }
        return Ok(Json(trimmed));
    }

    Ok(Json(response))
}

/// Build a `<mark>`-highlighted snippet around the first match of `q`
/// inside `haystack`. Falls back to the full haystack (unmarked) when
/// the match can't be located (shouldn't happen — we only call this
/// after a successful `contains` — but defend against it anyway).
///
/// The result is capped at MAX_SNIPPET_LEN bytes including the markup.
fn build_snippet(haystack: &str, q: &str) -> String {
    let h_lower = haystack.to_lowercase();
    let q_lower = q.to_lowercase();
    let Some(byte_idx) = h_lower.find(&q_lower) else {
        return truncate_chars(haystack, MAX_SNIPPET_LEN);
    };

    // Find the matched substring in the original casing — same byte
    // offsets work because to_lowercase() preserves byte positions for
    // ASCII and the catalog content is overwhelmingly ASCII. For the
    // odd non-ASCII char where to_lowercase changes the byte length,
    // fall back to a plain truncated view.
    let q_len = q_lower.len();
    let match_end = byte_idx + q_len;
    if !haystack.is_char_boundary(byte_idx) || !haystack.is_char_boundary(match_end) {
        return truncate_chars(haystack, MAX_SNIPPET_LEN);
    }
    let matched_original = &haystack[byte_idx..match_end];

    // Take ±SNIPPET_CONTEXT chars of context. Walk char boundaries
    // outward from the match so we don't slice a multibyte char.
    let before_start = nearest_left_boundary(haystack, byte_idx, SNIPPET_CONTEXT);
    let after_end = nearest_right_boundary(haystack, match_end, SNIPPET_CONTEXT);

    let before = &haystack[before_start..byte_idx];
    let after = &haystack[match_end..after_end];

    let leading_ellipsis = if before_start > 0 { "…" } else { "" };
    let trailing_ellipsis = if after_end < haystack.len() { "…" } else { "" };

    let snippet = format!(
        "{lead}{before}<mark>{matched}</mark>{after}{trail}",
        lead = leading_ellipsis,
        before = html_escape(before),
        matched = html_escape(matched_original),
        after = html_escape(after),
        trail = trailing_ellipsis,
    );

    // Hard cap on output length. If we go over, drop to a plain
    // truncated view to keep the response shape predictable.
    if snippet.len() > MAX_SNIPPET_LEN {
        // Try preserving the mark but trimming context further.
        let bare = format!(
            "<mark>{matched}</mark>",
            matched = html_escape(matched_original)
        );
        if bare.len() <= MAX_SNIPPET_LEN {
            return bare;
        }
        return truncate_chars(haystack, MAX_SNIPPET_LEN);
    }
    snippet
}

/// Walk `s` left from `mid` by up to `chars` Unicode chars, returning
/// the nearest valid char boundary.
fn nearest_left_boundary(s: &str, mid: usize, chars: usize) -> usize {
    let prefix = &s[..mid];
    let take = prefix.chars().rev().take(chars).count();
    let mut iter = prefix.char_indices().rev();
    let mut start = mid;
    for _ in 0..take {
        match iter.next() {
            Some((i, _)) => start = i,
            None => break,
        }
    }
    start
}

/// Walk `s` right from `mid` by up to `chars` Unicode chars, returning
/// the nearest valid char boundary.
fn nearest_right_boundary(s: &str, mid: usize, chars: usize) -> usize {
    let suffix = &s[mid..];
    let mut taken_bytes = 0usize;
    for (i, c) in suffix.char_indices().take(chars) {
        taken_bytes = i + c.len_utf8();
    }
    mid + taken_bytes
}

/// Truncate `s` to at most `max_bytes` while respecting char
/// boundaries. Appends an ellipsis when truncation actually happens.
fn truncate_chars(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    // Reserve a few bytes for the ellipsis.
    let budget = max_bytes.saturating_sub(3);
    let mut end = 0usize;
    for (i, c) in s.char_indices() {
        if i + c.len_utf8() > budget {
            break;
        }
        end = i + c.len_utf8();
    }
    let mut out = String::with_capacity(end + 3);
    out.push_str(&s[..end]);
    out.push('…');
    out
}

/// Escape the four HTML chars that could break the `<mark>` shell.
/// We deliberately don't escape inside `<mark>` ourselves — we wrap a
/// substring we know is safe (it came from the same `haystack` we just
/// escaped). The wrapping `<mark>` tags are literal.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_wraps_match_in_mark() {
        let s = build_snippet("Microsoft Edge Security STIG", "edge");
        assert!(s.contains("<mark>Edge</mark>"), "got: {s}");
    }

    #[test]
    fn snippet_truncates_long_text() {
        let big = "x".repeat(500);
        let body = format!("{big} edge {big}");
        let s = build_snippet(&body, "edge");
        assert!(s.len() <= MAX_SNIPPET_LEN, "len={}", s.len());
    }

    #[test]
    fn snippet_escapes_html() {
        let s = build_snippet("<script>edge</script>", "edge");
        assert!(s.contains("&lt;script&gt;"), "got: {s}");
        assert!(s.contains("<mark>edge</mark>"), "got: {s}");
    }
}
