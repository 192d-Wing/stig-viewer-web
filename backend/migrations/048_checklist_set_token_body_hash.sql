-- Bind retry tokens to the request content they were first used with.
--   create_body_sha256     hex SHA-256 of the canonical create request that
--                          stored create_key.
--   last_save_body_sha256  hex SHA-256 of the canonical autosave request that
--                          stored last_save_id.
-- A repeat of a token with different content is refused (409) instead of
-- being acknowledged as a replay. NULL for requests without a token and for
-- rows written before this migration (those tokens match any content).
-- The hash is an idempotency binding only; it is not a MAC or an integrity
-- control, and the tokens are not secrets.
-- Cleared wherever last_save_id is cleared.
ALTER TABLE checklist_sets
    ADD COLUMN IF NOT EXISTS create_body_sha256 TEXT NULL CHECK (length(create_body_sha256) = 64),
    ADD COLUMN IF NOT EXISTS last_save_body_sha256 TEXT NULL CHECK (length(last_save_body_sha256) = 64);
