-- Capture the STIG version + release that was current when each
-- checklist was created. Drift = applied_version != stigs_catalog.version
-- (or applied_release != stigs_catalog.release_info). Existing rows
-- get empty strings; the drift logic skips empties so legacy checklists
-- don't get flagged as outdated.
ALTER TABLE checklists
    ADD COLUMN applied_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN applied_release TEXT NOT NULL DEFAULT '';
