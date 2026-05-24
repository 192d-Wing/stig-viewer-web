-- Per-asset Access Control List.
--
-- The owner of an asset (assets.owner_id) and any user with the global
-- `admin` role retain unconditional mutate rights — those checks live in
-- the application layer. This table grants additional, per-user
-- permissions for non-owner / non-admin users:
--
--   read   — non-mutating (currently a no-op; reads are already open to
--            any authenticated user, but reserved for a future tighten-up)
--   write  — apply STIGs, patch rule statuses, upload/delete attachments,
--            bulk-import rules, etc.
--   admin  — everything `write` allows, plus mutate the asset row itself
--            (rename / classify / delete) and grant/revoke ACL entries.
--
-- Default behavior (no ACL rows) MUST match today's behavior — only the
-- asset owner (or a global admin) can mutate. This invariant is what
-- keeps the existing E2E suite green without modification.
CREATE TABLE asset_acl (
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission  TEXT NOT NULL,          -- 'read' | 'write' | 'admin'
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by  TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY (asset_id, user_id)
);

CREATE INDEX asset_acl_user_idx ON asset_acl(user_id);
