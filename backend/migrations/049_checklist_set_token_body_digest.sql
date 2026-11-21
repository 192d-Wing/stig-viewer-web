-- Self-describing replay digests for checklist-set retry tokens.
--   create_body_digest     "<algorithm>:<hex>" digest of the canonical create
--                          request that stored create_key.
--   last_save_body_digest  "<algorithm>:<hex>" digest of the canonical autosave
--                          request that stored last_save_id.
-- The algorithm tag lets the hash change later without another column swap;
-- the CHECK is deliberately not tied to one algorithm or length. The digest is
-- an idempotency binding only; it is not a MAC or an integrity control, and
-- the tokens are not secrets.
-- The 048 columns (create_body_sha256, last_save_body_sha256) are superseded:
-- the code reads only the new columns, but still writes the bare hex of a
-- sha256 digest into the old ones next to the new ones, so a rollback of the
-- code keeps working. A later migration drops them and the dual write.
-- Their existing values are copied here with the "sha256:" tag. Cleared
-- wherever last_save_id is cleared.
ALTER TABLE checklist_sets
    ADD COLUMN IF NOT EXISTS create_body_digest TEXT NULL
        CHECK (create_body_digest ~ '^[a-z0-9-]{1,32}:[0-9a-f]{32,255}$'),
    ADD COLUMN IF NOT EXISTS last_save_body_digest TEXT NULL
        CHECK (last_save_body_digest ~ '^[a-z0-9-]{1,32}:[0-9a-f]{32,255}$');

UPDATE checklist_sets SET create_body_digest = 'sha256:' || create_body_sha256
 WHERE create_body_sha256 ~ '^[0-9a-f]{64}$' AND create_body_digest IS NULL;
UPDATE checklist_sets SET last_save_body_digest = 'sha256:' || last_save_body_sha256
 WHERE last_save_body_sha256 ~ '^[0-9a-f]{64}$' AND last_save_body_digest IS NULL;

COMMENT ON COLUMN checklist_sets.create_body_sha256 IS
    'Superseded by create_body_digest (049); written only for rollback.';
COMMENT ON COLUMN checklist_sets.last_save_body_sha256 IS
    'Superseded by last_save_body_digest (049); written only for rollback.';
