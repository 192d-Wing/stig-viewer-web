-- Per-asset approval workflow for closing findings.
--
-- When `assets.requires_approval = TRUE`, transitions to a closing status
-- (not_a_finding / not_applicable) no longer apply directly. Instead a
-- `finding_approvals` row is created in `pending` state, and a reviewer
-- (or admin) must approve before the rule's status actually changes.
--
-- Default `requires_approval = FALSE` preserves the existing direct-close
-- behavior that the bulk of the E2E suite depends on.

ALTER TABLE assets
    ADD COLUMN requires_approval BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE finding_approvals (
    id              TEXT PRIMARY KEY,
    checklist_id    TEXT NOT NULL REFERENCES checklists(id) ON DELETE CASCADE,
    rule_id         TEXT NOT NULL,
    requested_by    TEXT NOT NULL REFERENCES users(id),
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    proposed_status TEXT NOT NULL,
    finding_details TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
                         -- 'pending' | 'approved' | 'rejected'
    decided_by      TEXT REFERENCES users(id),
    decided_at      TIMESTAMPTZ,
    decision_reason TEXT
);

CREATE INDEX finding_approvals_pending_idx
    ON finding_approvals(status, requested_at DESC)
    WHERE status = 'pending';

CREATE INDEX finding_approvals_requester_idx
    ON finding_approvals(requested_by, decided_at DESC);

CREATE INDEX finding_approvals_rule_idx
    ON finding_approvals(checklist_id, rule_id);
