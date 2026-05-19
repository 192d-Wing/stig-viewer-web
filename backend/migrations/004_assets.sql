-- Systems / assets being tracked for STIG compliance.
-- Each asset has a single owner (the user who created it). For MVP any
-- authenticated user can list and read all assets, but only the owner
-- can update or delete.
CREATE TABLE assets (
    id             TEXT PRIMARY KEY,
    name           TEXT        NOT NULL,
    hostname       TEXT        NOT NULL DEFAULT '',
    description    TEXT        NOT NULL DEFAULT '',
    classification TEXT        NOT NULL DEFAULT 'unclassified',
    owner_id       TEXT        NOT NULL REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX assets_owner_idx ON assets(owner_id);
