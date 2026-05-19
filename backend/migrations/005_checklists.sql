-- A checklist = applying a specific STIG to a specific asset.
-- One asset can have multiple checklists (different STIGs);
-- the (asset_id, stig_id) pair is unique.
CREATE TABLE checklists (
    id         TEXT PRIMARY KEY,
    asset_id   TEXT        NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    stig_id    TEXT        NOT NULL,
    status     TEXT        NOT NULL DEFAULT 'in_progress',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, stig_id)
);

CREATE INDEX checklists_asset_idx ON checklists(asset_id);
CREATE INDEX checklists_stig_idx  ON checklists(stig_id);

-- One row per rule whose state has been *modified*. Rules with no row
-- are implicitly 'not_reviewed' with empty finding_details / comments.
-- Avoids 300+ inserts per checklist creation.
CREATE TABLE checklist_rules (
    checklist_id    TEXT        NOT NULL REFERENCES checklists(id) ON DELETE CASCADE,
    rule_id         TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'not_reviewed',
    finding_details TEXT        NOT NULL DEFAULT '',
    comments        TEXT        NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      TEXT        REFERENCES users(id),
    PRIMARY KEY (checklist_id, rule_id)
);

CREATE INDEX checklist_rules_status_idx ON checklist_rules(status);
