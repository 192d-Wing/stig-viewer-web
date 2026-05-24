-- Named, persisted snapshots of per-rule compliance state. Used by the
-- dashboard "changes since baseline" diff.
CREATE TABLE baselines (
    id         TEXT PRIMARY KEY,
    name       TEXT        NOT NULL UNIQUE,
    created_by TEXT        NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-rule state captured at baseline-creation time. Only rules that had
-- a row in checklist_rules at baseline time are stored — rules that were
-- never touched (implicit 'not_reviewed') are not captured. The diff
-- endpoint therefore won't surface a "not_reviewed → Open" transition for
-- rules that had no override row at baseline time. Acceptable for MVP;
-- a FULL OUTER JOIN with NULL→'not_reviewed' coalesce on both sides
-- would close the gap if it ever bites.
CREATE TABLE baseline_rules (
    baseline_id  TEXT NOT NULL REFERENCES baselines(id) ON DELETE CASCADE,
    checklist_id TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    status       TEXT NOT NULL,
    PRIMARY KEY (baseline_id, checklist_id, rule_id)
);

CREATE INDEX baseline_rules_checklist_idx ON baseline_rules(checklist_id);
