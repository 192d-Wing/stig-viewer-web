-- Drafts can target a specific reviewer.
--
-- When `assigned_reviewer_id` is NULL the existing "any reviewer can claim
-- it" semantics apply. When set, only that reviewer (or an admin) may
-- transition the draft through review/approve/reject. ON DELETE SET NULL
-- so removing a user falls back to the open-pool behaviour.
ALTER TABLE stig_drafts
    ADD COLUMN assigned_reviewer_id TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_drafts_assigned_reviewer
    ON stig_drafts(assigned_reviewer_id);
