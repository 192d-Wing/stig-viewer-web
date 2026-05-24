-- Append-only audit trail for checklist_rules changes. One row per
-- (rule, changed-field) per PATCH; a multi-field update writes N rows
-- in the same transaction. Stores the full from/to values rather than
-- truncating — disk is cheap and the forensic value of full strings
-- (finding_details, comments) is high.
CREATE TABLE rule_audit (
    id           BIGSERIAL PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id      TEXT        NOT NULL REFERENCES users(id),
    checklist_id TEXT        NOT NULL,
    rule_id      TEXT        NOT NULL,
    field        TEXT        NOT NULL,
    from_value   TEXT,
    to_value     TEXT
);

CREATE INDEX rule_audit_rule_idx     ON rule_audit(checklist_id, rule_id, occurred_at DESC);
CREATE INDEX rule_audit_occurred_idx ON rule_audit(occurred_at DESC);
CREATE INDEX rule_audit_user_idx     ON rule_audit(user_id, occurred_at DESC);
