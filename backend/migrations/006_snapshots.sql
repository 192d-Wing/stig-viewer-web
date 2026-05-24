-- Daily snapshots of per-checklist compliance posture. Append-only;
-- a row per (captured_at, checklist_id) pair captures the rule-status
-- counts at that point in time. Powers the dashboard trend charts.
CREATE TABLE checklist_snapshots (
    captured_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checklist_id   TEXT        NOT NULL REFERENCES checklists(id) ON DELETE CASCADE,
    asset_id       TEXT        NOT NULL REFERENCES assets(id)     ON DELETE CASCADE,
    stig_id        TEXT        NOT NULL,
    rule_count     INTEGER     NOT NULL,
    open_count     INTEGER     NOT NULL,
    naf_count      INTEGER     NOT NULL,
    na_count       INTEGER     NOT NULL,
    reviewed_count INTEGER     NOT NULL,
    PRIMARY KEY (captured_at, checklist_id)
);

CREATE INDEX checklist_snapshots_captured_idx ON checklist_snapshots(captured_at);
CREATE INDEX checklist_snapshots_asset_idx    ON checklist_snapshots(asset_id, captured_at);
