-- Per-user review state for a given STIG: asset metadata (hostname, IP, etc.)
-- and per-rule status / finding-details / comments. The STIG catalog row is
-- the source of truth for the rules themselves; workspaces only store user
-- overrides keyed by rule_id.
CREATE TABLE IF NOT EXISTS workspaces (
    id              BIGSERIAL   PRIMARY KEY,
    user_sub        TEXT        NOT NULL,
    stig_id         TEXT        NOT NULL,
    asset_info      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    rule_overrides  JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_sub, stig_id)
);

CREATE INDEX IF NOT EXISTS idx_workspaces_user ON workspaces (user_sub);
CREATE INDEX IF NOT EXISTS idx_workspaces_updated ON workspaces (updated_at DESC);
