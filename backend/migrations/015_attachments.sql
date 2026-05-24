-- Evidence attachments uploaded against a specific rule on a checklist.
-- The blob itself lives at ${data_dir}/attachments/${id} on disk; only
-- the metadata lives in postgres so the table stays small.
CREATE TABLE attachments (
    id            TEXT PRIMARY KEY,
    checklist_id  TEXT NOT NULL REFERENCES checklists(id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    filename      TEXT NOT NULL,
    mime_type     TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    sha256        TEXT NOT NULL,
    uploaded_by   TEXT NOT NULL REFERENCES users(id),
    uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX attachments_checklist_rule_idx ON attachments(checklist_id, rule_id);
