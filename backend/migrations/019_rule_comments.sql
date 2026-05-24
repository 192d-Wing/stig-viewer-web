-- Per-rule comment threads.
--
-- Today, `checklist_rules.comments` is a single TEXT field that gets
-- overwritten on each PATCH (treat that as a "status note"). This table
-- is a separate, append-only threaded discussion keyed by
-- (checklist_id, rule_id), persisted independently of status updates.
CREATE TABLE rule_comments (
    id           TEXT PRIMARY KEY,
    checklist_id TEXT NOT NULL REFERENCES checklists(id) ON DELETE CASCADE,
    rule_id      TEXT NOT NULL,
    user_id      TEXT NOT NULL REFERENCES users(id),
    body         TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edited_at    TIMESTAMPTZ NULL
);

CREATE INDEX rule_comments_checklist_rule_idx
  ON rule_comments(checklist_id, rule_id, created_at);
