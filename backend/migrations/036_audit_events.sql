-- Durable, request-level audit events (bulk status change, save to system,
-- checklist creation), including rejected and denied requests. Unlike
-- `rule_audit` (one row per rule field change) this records the request.
-- asset_id / checklist_id / stig_id deliberately have no foreign keys so a
-- record outlives the deletion of what it refers to. Retention and backup
-- cover this table like `rule_audit`.
CREATE TABLE audit_events (
    id           BIGSERIAL PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id      TEXT        NOT NULL REFERENCES users(id),
    action       TEXT        NOT NULL,  -- 'rules.bulk_status' | 'checklist.save' | 'checklist.create'
    outcome      TEXT        NOT NULL,  -- 'ok' | 'partial' | 'denied' | 'rejected'
    asset_id     TEXT,
    checklist_id TEXT,
    stig_id      TEXT,
    detail       JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_occurred_idx ON audit_events(occurred_at DESC);
CREATE INDEX audit_events_user_idx     ON audit_events(user_id, occurred_at DESC);
CREATE INDEX audit_events_asset_idx    ON audit_events(asset_id, occurred_at DESC);

-- Who created the checklist. NULL = unknown (rows that predate this column;
-- deliberately not backfilled).
ALTER TABLE checklists ADD COLUMN created_by TEXT NULL REFERENCES users(id);
