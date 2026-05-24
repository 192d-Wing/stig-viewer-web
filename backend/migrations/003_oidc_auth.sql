-- Replace the X-User-Id placeholder auth with OIDC.
-- Wipe existing placeholder rows (cascades to drafts and comments).
TRUNCATE TABLE draft_comments, stig_drafts, users RESTART IDENTITY CASCADE;

-- OIDC identifying fields. (provider, sub) is the natural key from the IdP.
-- For the test-only X-User-Id bypass we set provider='test'.
ALTER TABLE users ADD COLUMN sub      TEXT NOT NULL;
ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'oidc';

CREATE UNIQUE INDEX users_provider_sub_key ON users(provider, sub);

-- Server-side sessions. Opaque random ID lives in an HttpOnly cookie.
CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_user_id_idx    ON sessions(user_id);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);
