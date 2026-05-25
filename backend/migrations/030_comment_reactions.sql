-- Emoji-style reactions on threaded rule comments.
--
-- One user can place at most one of each reaction type per comment. The
-- allowlist (thumbs_up, check, question) is enforced in the API layer so
-- new reaction types don't require a schema migration.
CREATE TABLE comment_reactions (
    comment_id  TEXT NOT NULL REFERENCES rule_comments(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reaction    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (comment_id, user_id, reaction)
);

CREATE INDEX comment_reactions_comment_idx ON comment_reactions(comment_id);
