-- Per-finding assignment + due date. Nullable on both — most rules
-- in a fresh checklist are unassigned with no deadline.
ALTER TABLE checklist_rules
    ADD COLUMN assignee_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN due_date    DATE;

-- Index used by /api/findings?assignee=<id> and by "Mine" drill-down filter.
CREATE INDEX checklist_rules_assignee_idx ON checklist_rules(assignee_id);
