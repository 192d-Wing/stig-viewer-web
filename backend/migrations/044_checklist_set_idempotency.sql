-- Retry safety for checklist sets.
--   create_key    client-chosen UUID sent with POST /api/checklist-sets; a
--                 repeat by the same owner returns the set it created instead
--                 of making another. Lives and dies with the set.
--   last_save_id  client-chosen UUID of the autosave that last bumped the
--                 revision; a repeat of exactly that request (one revision
--                 behind) is acknowledged instead of reported as a conflict.
-- Any other revision bump (removing a STIG) clears last_save_id.
-- Both are NULL for sets and saves that do not send a token.
ALTER TABLE checklist_sets
    ADD COLUMN IF NOT EXISTS create_key TEXT NULL CHECK (length(create_key) <= 36),
    ADD COLUMN IF NOT EXISTS last_save_id TEXT NULL CHECK (length(last_save_id) <= 36);

CREATE UNIQUE INDEX IF NOT EXISTS idx_checklist_sets_create_key
    ON checklist_sets (owner_id, create_key) WHERE create_key IS NOT NULL;
