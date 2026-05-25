-- Session activity audit + admin revoke.
--
-- Captures the IP and User-Agent of every session-creating login so the
-- admin console can show "who's logged in from where" and revoke a
-- specific session without invalidating every other session for the
-- user. Migration 003 already added a `created_at` column to `sessions`
-- so it isn't re-added here — only the audit-specific columns are new.
--
-- `revoked_at` is NULL for an active session and stamped to NOW() when
-- an admin revokes it via DELETE /api/admin/sessions/:id. The session
-- lookup path in `auth::resolve_session_user` filters on
-- `revoked_at IS NULL` so revocation takes effect on the next request.
ALTER TABLE sessions
    ADD COLUMN ip         TEXT        NOT NULL DEFAULT '',
    ADD COLUMN user_agent TEXT        NOT NULL DEFAULT '',
    ADD COLUMN revoked_at TIMESTAMPTZ NULL;

-- Partial index — the admin "active sessions" query filters
-- `revoked_at IS NULL` and there's no point indexing the revoked rows.
CREATE INDEX sessions_user_active_idx
    ON sessions(user_id, revoked_at)
    WHERE revoked_at IS NULL;
