-- Users (designed for OIDC/CAC, placeholder auth for now)
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    display_name TEXT        NOT NULL,
    email        TEXT        NOT NULL DEFAULT '',
    role         TEXT        NOT NULL DEFAULT 'author',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- STIG drafts
CREATE TABLE IF NOT EXISTS stig_drafts (
    id            TEXT PRIMARY KEY,
    title         TEXT        NOT NULL DEFAULT '',
    author_id     TEXT        NOT NULL REFERENCES users(id),
    based_on_stig TEXT,
    status        TEXT        NOT NULL DEFAULT 'draft',
    version       TEXT        NOT NULL DEFAULT '1',
    release_info  TEXT        NOT NULL DEFAULT '',
    description   TEXT        NOT NULL DEFAULT '',
    next_vuln_id  INTEGER     NOT NULL DEFAULT 100001,
    json_path     TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_drafts_author ON stig_drafts(author_id);
CREATE INDEX IF NOT EXISTS idx_drafts_status ON stig_drafts(status);

-- Review comments / approval actions
CREATE TABLE IF NOT EXISTS draft_comments (
    id         TEXT PRIMARY KEY,
    draft_id   TEXT        NOT NULL REFERENCES stig_drafts(id) ON DELETE CASCADE,
    user_id    TEXT        NOT NULL REFERENCES users(id),
    body       TEXT        NOT NULL,
    action     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comments_draft ON draft_comments(draft_id);
