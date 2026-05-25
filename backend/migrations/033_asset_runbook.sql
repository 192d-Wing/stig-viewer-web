-- Per-asset free-form markdown runbook.
--
-- Operators need a place to capture operational notes for each system:
-- escalation contacts, known issues, restart procedures, etc. We park
-- the content directly on the asset row as a single TEXT column rather
-- than a separate "asset_notes" table — runbook content is small,
-- always read in lockstep with the asset, and version history is not a
-- requirement right now.
--
-- NOT NULL DEFAULT '' keeps the rest of the codebase honest: every
-- asset row always has a runbook string, even if empty. The HTTP layer
-- treats an empty string as "no runbook yet" and the frontend renders
-- a placeholder.
--
-- Read-side has a soft 100 KB defensive truncation in `db_assets.rs`
-- so a runaway runbook can't blow up an API response. Writes are not
-- capped today — the column is plain TEXT and an oversize write will
-- simply round-trip through the truncator on the next read.
ALTER TABLE assets
    ADD COLUMN runbook TEXT NOT NULL DEFAULT '';
