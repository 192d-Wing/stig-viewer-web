-- Multi-tenant organisations.
--
-- Every data-carrying row (catalog, workspaces, audit_log) gains an
-- `org_id` column so queries can scope to the caller's active org. A
-- built-in "default" organisation absorbs all pre-existing rows so the
-- migration is zero-downtime on live deployments.

CREATE TABLE IF NOT EXISTS organizations (
    id          BIGSERIAL   PRIMARY KEY,
    slug        TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed the default org. Any later migration that changes the default is
-- expected to keep slug='default' addressable.
INSERT INTO organizations (slug, name)
VALUES ('default', 'Default organisation')
ON CONFLICT (slug) DO NOTHING;

-- Many-to-many between users (actor_sub / session.sub) and organisations.
CREATE TABLE IF NOT EXISTS org_memberships (
    org_id      BIGINT      NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_sub    TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_sub)
);

CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON org_memberships (user_sub);

-- Add org_id to the three data tables. Default to the seeded default org so
-- existing rows land in the expected tenant; the column is NOT NULL going
-- forward. Drop the default once all callers set it explicitly (future
-- migration — kept as DEFAULT for now so rolling deploys don't break).
DO $$
DECLARE
    default_org_id BIGINT;
BEGIN
    SELECT id INTO default_org_id FROM organizations WHERE slug = 'default';

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'stigs_catalog' AND column_name = 'org_id'
    ) THEN
        EXECUTE format(
            'ALTER TABLE stigs_catalog ADD COLUMN org_id BIGINT NOT NULL DEFAULT %s REFERENCES organizations(id)',
            default_org_id
        );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'workspaces' AND column_name = 'org_id'
    ) THEN
        EXECUTE format(
            'ALTER TABLE workspaces ADD COLUMN org_id BIGINT NOT NULL DEFAULT %s REFERENCES organizations(id)',
            default_org_id
        );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_log' AND column_name = 'org_id'
    ) THEN
        EXECUTE format(
            'ALTER TABLE audit_log ADD COLUMN org_id BIGINT NOT NULL DEFAULT %s REFERENCES organizations(id)',
            default_org_id
        );
    END IF;
END
$$;

-- stigs_catalog: the id is still globally unique (filesystem path depends
-- on it), but scoped queries happen by (org_id, id). Index for the common
-- lookup.
CREATE INDEX IF NOT EXISTS idx_stigs_catalog_org ON stigs_catalog (org_id);

-- workspaces: replace the old UNIQUE(user_sub, stig_id) with the
-- org-scoped triple so two orgs can independently review the same STIG.
ALTER TABLE workspaces DROP CONSTRAINT IF EXISTS workspaces_user_sub_stig_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_workspaces_org_user_stig
    ON workspaces (org_id, user_sub, stig_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_org ON audit_log (org_id);
