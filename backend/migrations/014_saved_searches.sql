-- Per-user named bookmarks of a URL query string for a specific page.
-- Used by My Findings (and other filter-heavy pages) to recall a complex
-- filter set by name. The (user_id, page, name) UNIQUE constraint makes
-- it safe to save the same name across pages but not on the same page.
CREATE TABLE saved_searches (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    page       TEXT NOT NULL,  -- e.g. "myfindings", "dashboard"
    name       TEXT NOT NULL,
    params     TEXT NOT NULL,  -- query string, e.g. "severity=CAT+I&pastDue=true"
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, page, name)
);

CREATE INDEX saved_searches_user_page_idx ON saved_searches(user_id, page);
