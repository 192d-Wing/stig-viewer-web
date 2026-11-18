-- Checklist sets: named, owner-private working checklists that hold one or
-- more catalog STIGs. State is sparse (only touched rules have rows), like
-- checklists / checklist_rules. `revision` is the optimistic-concurrency
-- counter for autosave; `asset_id` is the system the set was last saved to.
CREATE TABLE IF NOT EXISTS checklist_sets (
    id                  TEXT        PRIMARY KEY,
    owner_id            TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,
    asset_id            TEXT        NULL REFERENCES assets(id) ON DELETE SET NULL,
    revision            BIGINT      NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attached_at    TIMESTAMPTZ NULL,
    last_edit_event_at  TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_checklist_sets_owner ON checklist_sets (owner_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_checklist_sets_asset ON checklist_sets (asset_id);

CREATE TABLE IF NOT EXISTS checklist_set_stigs (
    set_id           TEXT        NOT NULL REFERENCES checklist_sets(id) ON DELETE CASCADE,
    stig_id          TEXT        NOT NULL,
    position         INT         NOT NULL,
    applied_version  TEXT        NOT NULL DEFAULT '',
    applied_release  TEXT        NOT NULL DEFAULT '',
    added_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (set_id, stig_id)
);

CREATE TABLE IF NOT EXISTS checklist_set_rules (
    set_id           TEXT        NOT NULL,
    stig_id          TEXT        NOT NULL,
    rule_id          TEXT        NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'not_reviewed',
    finding_details  TEXT        NOT NULL DEFAULT '',
    comments         TEXT        NOT NULL DEFAULT '',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (set_id, stig_id, rule_id),
    FOREIGN KEY (set_id, stig_id) REFERENCES checklist_set_stigs (set_id, stig_id) ON DELETE CASCADE
);
